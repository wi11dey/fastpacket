#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <netinet/ip.h>

#define STACK_SIZE (1024 * 1024) // How big of a stack to give the sandboxed process (1 MiB)
#define NUM_KIDS 3 // How many child (guest) processes to allow

static char stack[STACK_SIZE]; // Child's stack goes in bss segment

typedef struct {
  pid_t pid;
  enum SyscallEvent {
    SYSCALL_ENTER = 0,
    SYSCALL_EXIT = !SYSCALL_ENTER,
    SYSCALL_BLOCKED
  } next;
  struct user_regs_struct registers;
} Child;

int sandbox(void* argv) {
  // argv is guaranteed to be of length 3 because the check has been done in main
  char* guest_dir = ((char**) argv)[1];
  uid_t uid = atoi(((char**) argv)[2]);

  // Change working directory to guest_dir
  if (chdir(guest_dir)) {
    perror("Sandbox failed to change directory");
    return EXIT_FAILURE;
  }

  // Part 2: setuid() restrictions
  // Drop to non-root uid
  if (setuid(uid)) {
    perror("Sandbox failed to drop root");
    return EXIT_FAILURE;
  }

  // Begin tracing
  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
    perror("Sandbox failed to request tracing");
    return EXIT_FAILURE;
  }

  // Execute guest.pyc using python3
  if (execlp("python3", "python3", "guest.pyc", NULL) == -1) {
    perror("Sandbox failed to execute guest");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <directory containing guest.pyc> <user id to execute guest.pyc as>\n", argv[0]);
    return EXIT_FAILURE;
  }

  // Part 1: pid namespacing
  pid_t pid = clone(sandbox,
                    stack + STACK_SIZE, // Stack grows downward, so we need to start at the topmost address of the stack
                    CLONE_NEWPID,
                    argv);
  if (pid == -1) {
    perror("Failed to clone into sandbox");
    return EXIT_FAILURE;
  }

  sleep(1); // Sleep for a section to ensure that the child process has been created before we wait on it

  // Part 3: fork() restrictions
  int status;
  // Wait for the firstborn to call PTRACE_TRACEME
  if (waitpid(pid, &status, 0) == -1) {
    perror("Failed to wait for firstborn");
    return EXIT_FAILURE;
  }
  if (WIFEXITED(status)) {
    fprintf(stderr, "Firstborn died before it asked to be traced\n");
    return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
  }
  // Trace any additional processes the child spawns, make it easy to distinguish syscalls, and also take it down with us if we die
  if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK  | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
    perror("Failed to set ptrace options");
    return EXIT_FAILURE;
  }

  // Release the firstborn but watch for any syscalls
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
    perror("Failed to watch for firstborn's syscalls");
    return EXIT_FAILURE;
  }

  Child kids[NUM_KIDS] = { { pid } }; // A flag for whether or not a child's syscall is running is not needed, since I wait for syscalls to finish synchronously before waiting on a different child (see below)
  
  while (true) {
    // Wait for any child to change state
    pid = wait(&status);
    if (pid == -1) {
      perror("Failed to wait for children");
      return EXIT_FAILURE;
    }

    // Figure out what happened
    if (WIFEXITED(status) || WIFSIGNALED(status)) { // Check whether the traced guest process has died
      bool kids_remain = false; // This will let us know if there are no more children left
      unsigned int i;
      for (i = 0; i < sizeof(kids) / sizeof(Child); i++) {
        if (!kids[i].pid) {
          continue;
        } else if (kids[i].pid == pid) {
          kids[i] = (Child) { 0 }; // Clear the dead child's slot
        } else {
          kids_remain = true;
        }
      }
      if (!kids_remain) {
        // No more kids; we can retire
        return EXIT_SUCCESS;
      }
      continue;
    } else if (WIFSTOPPED(status)) { // Recieved a signal
      int signal = WSTOPSIG(status);
      if (signal == (SIGTRAP | 0x80)) { // Syscall event
        bool too_many_kids = true;
        unsigned int i;
        for (i = 0; i < sizeof(kids) / sizeof(Child); i++) {
          if (!kids[i].pid) {
            // There is an open spot
            too_many_kids = false;
            kids[i] = (Child) { pid, SYSCALL_EXIT };
            break;
          } else if (kids[i].pid == pid) {
            // We are already watching this child
            too_many_kids = false;
            switch (kids[i].next) {
            case SYSCALL_EXIT:
              kids[i].next = SYSCALL_ENTER;
              break;
            case SYSCALL_BLOCKED:
	      kids[i].registers.rax = -EPERM;
	      if (ptrace(PTRACE_SETREGS, pid, NULL, &kids[i].registers) == -1) {
		perror("Failed to set error return value of blocked syscall");
		return EXIT_FAILURE;
	      }
              kids[i].next = SYSCALL_ENTER;
              break;
            case SYSCALL_ENTER:
              {
                // Part 4: connect() restriction
                struct user_regs_struct registers;
                if (ptrace(PTRACE_GETREGS, pid, NULL, &registers)) {
                  perror("Failed to get registers at child's syscall");
                  return EXIT_FAILURE;
                }
                kids[i].registers = registers;
                bool allow = true;
                switch (registers.orig_rax) {
                case SYS_connect:
                  {
                    struct sockaddr_in* addr = (struct sockaddr_in*) registers.rsi;
                    union in_addr_words {
                      struct in_addr in_addr;
                      uint64_t words[(sizeof(struct in_addr) + sizeof(uint64_t) - 1) / sizeof(uint64_t)];
                    } sin_addr;
                    unsigned int i;
                    for (i = 0; i < sizeof(union in_addr_words) / sizeof(uint64_t); i++) {
                      errno = 0;
                      uint64_t word = ptrace(PTRACE_PEEKDATA, pid, &addr->sin_addr + i);
                      if (errno) {
                        perror("Failed to read IP address of connect call");
			return EXIT_FAILURE;
                      }
                      sin_addr.words[i] = word;
                    }
                    if ((sin_addr.in_addr.s_addr   & 0x00FFFFFF)
			!= (htonl(INADDR_LOOPBACK) & 0x00FFFFFF)) {
                      allow = false;
                      break;
                    }
                  }
		  break;
                }
		if (allow) {
		  kids[i].next = SYSCALL_EXIT;
		} else {
		  registers.orig_rax = -1;
		  if (ptrace(PTRACE_SETREGS, pid, NULL, &registers) == -1) {
		    perror("Failed to block syscall");
		    return EXIT_FAILURE;
		  }
		  kids[i].next = SYSCALL_BLOCKED;
		}
              }
	      break;
            }
            break;
          }
        }
        if (too_many_kids) {
          // Someone's gotta go
          if (kill(pid, SIGKILL) == -1) {
            perror("Failed to kill extra child");
            return EXIT_FAILURE;
          }
          continue;
        }
      } else {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) == -1) {
          perror("Failed to replay child's signal");
          return EXIT_FAILURE;
        }
        continue;
      }
    }

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
      perror("Failed to watch for child's syscalls");
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
}
