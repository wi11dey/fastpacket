#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#define STACK_SIZE (1024 * 1024) // How big of a stack to give the sandboxed process (1 MiB)
#define NUM_KIDS 3 // How many child (guest) processes to allow

static char stack[STACK_SIZE]; // Child stack goes in bss segment

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
  setuid(uid);

  // Begin tracing
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);

  // Execute guest.pyc using python3
  execlp("python3", "python3", "guest.pyc", NULL);
  return EXIT_SUCCESS;
}

pid_t wait_for_syscall(pid_t awaited_pid, size_t num_kids, pid_t* kids) {
  printf("wait_for_syscall %d\n", awaited_pid);
  int status;
  // Wait for any child to change state
  pid_t pid = waitpid(awaited_pid, &status, 0);
  if (pid == -1) {
    perror("Failed to wait for children");
    return EXIT_FAILURE;
  }

  // Figure out what happened
  if (WIFEXITED(status)) { // Check whether the traced guest process has died
    bool kids_remain = false; // This will let us know if there are no more children left
    int i = 0;
    for (i = 0; i < sizeof(kids) / sizeof(pid_t); i++) {
      if (!kids[i]) {
        continue;
      } else if (kids[i] == pid) {
        kids[i] = 0;
      } else {
        kids_remain = true;
      }
    }
    if (!kids_remain) {
      // No more kids; we can retire
      exit(EXIT_SUCCESS);
    }
    return -1;
  } else if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) { // Recieved a signal
    int signal = WSTOPSIG(status);
    if (signal == (SIGTRAP | 0x80)) { // Invoked a syscall
      bool too_many_kids = true;
      int i = 0;
      for (i = 0; i < sizeof(kids) / sizeof(pid_t); i++) {
        if (!kids[i]) {
          // There is an open spot
          kids[i] = pid;
        }
        if (kids[i] == pid) {
          // We are already watching this child
          too_many_kids = false;
          break;
        }
      }
      if (too_many_kids) {
        // Someone's gotta go
        if (kill(pid, SIGKILL) == -1) {
          perror("Failed to kill extra child");
          exit(EXIT_FAILURE);
        }
        return -1;
      }

      return pid; // Tell caller to handle the syscall
    } else {
      if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) == -1) {
        perror("Failed to replay child's signal");
        exit(EXIT_FAILURE);
      }
      return 0;
    }
  } else {
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
      perror("Failed to watch for child's syscalls");
      exit(EXIT_FAILURE);
    }
    return 0;
  }
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

  pid_t kids[NUM_KIDS] = { pid, 0, 0 }; // A flag for whether or not a child's syscall is running is not needed, since I wait for syscalls to finish synchronously before waiting on a different child (see below)
  
  while (true) {
    pid = wait_for_syscall(-1, sizeof(kids) / sizeof(pid_t), kids);
    if (pid > 0) {
      if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("Failed to watch for child's return from syscall");
        return EXIT_FAILURE;
      }
      while (true) {
        // Wait for this child specifically to return from the syscall
        pid_t state = wait_for_syscall(pid, sizeof(kids) / sizeof(pid_t), kids);
        if (state == -1) {
          break; // Child has died
        } else if (state == 0) {
          continue; // A different kind of signal was caught and handled, so we need to wait again
        } else {
          // Continue watching for future syscalls
          if (ptrace(PTRACE_SYSCALL, state, NULL, NULL) == -1) {
            perror("Failed to watch for child's syscalls");
            return EXIT_FAILURE;
          }
        }
      }
    }
  }

  return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
}
