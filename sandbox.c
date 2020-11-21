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

/**
 * Struct to represent a child process currently being traced.
 */
typedef struct {
  /**
   * Process ID of the child, from the perspective of the sandboxer.
   */
  pid_t pid;

  /**
   * Enum representing what we expect from the child the next time it stops for a syscall.
   */
  enum SyscallEvent {
    /** 
     * No syscall is currently in flight, so the next syscall stop must be right before a new syscall is made to the kernel.
     */
    SYSCALL_ENTER = 0,

    /**
     * A syscall is currently being executed, so the next syscall stop must be right before the return to user mode.
     */
    SYSCALL_EXIT = !SYSCALL_ENTER, // Defined as the inverse of SYSCALL_ENTER, so they can be toggled with the ! operator

    /**
     * Similar to SYSCALL_EXIT, but indicates that the sandboxer blocked the syscall, so the return value should be set to -EPERM.
     */
    SYSCALL_BLOCKED
  } next;

  /**
   * The registers captured during the last SYSCALL_ENTER, right before the kernel executes the syscall. Useful for when the syscall's return value needs to be modified.
   */
  struct user_regs_struct registers;
} Child;

/**
 * The function called during clone to sandbox the guest.
 *
 * argv's true type must be a string array (char**) of length 3:
 *   [0]: The 0th element is ignored
 *   [1]: The 1th element must be the directory where guest.pyc is located, which will be used as the working directory during the guest's execution
 *   [2]: The 2nd element must be the user ID to run the guest as
 */
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

  Child kids[NUM_KIDS] = { { pid } }; // The only child being watched is the firstborn; all other slots are zero-initialized by the C99 specification. The firstborn's next SyscallEvent defaults to SYSCALL_ENTER
  
  while (true) {
    // Wait for any child to change state
    pid = wait(&status);
    if (pid == -1) {
      perror("Failed to wait for children");
      return EXIT_FAILURE;
    }

    // Figure out what happened
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      // A child has died
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
    } else if (WIFSTOPPED(status)) {
      // A child has been stopped, due to some signal
      int signal = WSTOPSIG(status);
      if (signal == (SIGTRAP | 0x80)) { // Syscall event
        // Part 3: fork() restrictions
        // Check if the child that made this syscall exceeds the three-child policy
        bool too_many_kids = true;
        unsigned int i;
        for (i = 0; i < sizeof(kids) / sizeof(Child); i++) {
          if (!kids[i].pid) {
            // There is an open spot for this kid
            too_many_kids = false;

            // Fill the spot with a new Child entry
            kids[i] = (Child) { pid, SYSCALL_EXIT }; // This was the SYSCALL_ENTER, so the next SyscallEvent we are expecting from this child is the SYSCALL_EXIT
            break;
          } else if (kids[i].pid == pid) {
            // We are already watching this child
            too_many_kids = false;

            // Figure out what to do based on what kind of SyscallEvent this is
            switch (kids[i].next) { // The SyscallEvent that was predicted to be next will tell us what to do
            case SYSCALL_EXIT:
              // The syscall finished and was allowed; wait for the next syscall to start
              kids[i].next = SYSCALL_ENTER;
              break;

            case SYSCALL_BLOCKED:
              // The syscall was blocked, so now we need to set the return value to a descriptive error
              kids[i].registers.rax = -EPERM; // "Operation not permitted"
              if (ptrace(PTRACE_SETREGS, pid, NULL, &kids[i].registers) == -1) {
                perror("Failed to set error return value of blocked syscall");
                return EXIT_FAILURE;
              }

              // Wait for the next syscall
              kids[i].next = SYSCALL_ENTER;
              break;

            case SYSCALL_ENTER:
              // A syscall is about to be executed. We need to examine it to determine if it should be blocked
              {
                // Part 4: connect() restriction
                struct user_regs_struct registers;
                if (ptrace(PTRACE_GETREGS, pid, NULL, &registers)) {
                  perror("Failed to get registers at child's syscall");
                  return EXIT_FAILURE;
                }

                // Allow-by-default, unless we determine that this specific invocation needs to be blocked
                bool allow = true;
                switch (registers.orig_rax) { // Choose what we do based on what syscall this is
                case SYS_connect:
                  {
                    // The second argument (%rsi) to connect() is a pointer to the IP address, in the child process' memory
                    struct sockaddr_in* addr = (struct sockaddr_in*) registers.rsi;

                    // Use a union to make reinterpreting the bytes we read from the child's memory into a struct in_addr easy
                    union in_addr_words {
                      struct in_addr in_addr;
                      uint64_t words[(sizeof(struct in_addr) + sizeof(uint64_t) - 1) / sizeof(uint64_t)]; // Divide the size of a struct in_addr by the size of a 64-bit word, rounding up to make sure we cover the entire struct in_addr
                    } sin_addr;

                    // Fill out the union with words we read from the child process memory
                    unsigned int i;
                    for (i = 0; i < sizeof(union in_addr_words) / sizeof(uint64_t); i++) { // The size of union in_addr_words will be the minimum number of words to peek in order to read a full struct in_addr, because of the arithmetic done above
                      errno = 0;
                      uint64_t word = ptrace(PTRACE_PEEKDATA, pid, &addr->sin_addr + i); // &addr->sin_addr will give the correct starting offset for the sin_addr field within the struct sockaddr_in located at addr
                      if (errno) {
                        perror("Failed to read IP address of connect call");
                        return EXIT_FAILURE;
                      }
                      sin_addr.words[i] = word;
                    }

                    // Everything except the last octect should match the loopback address 127.0.0.1 exactly
                    if ((sin_addr.in_addr.s_addr   & 0x00FFFFFF)
                        != (htonl(INADDR_LOOPBACK) & 0x00FFFFFF)) {
                      // The IP address was not of the form 127.0.0.* so it needs to be disallowed
                      allow = false;
                      break;
                    }
                  }
                  break;
                }

                if (allow) {
                  // The syscall should be allowed and nothing special should be done when it exits
                  kids[i].next = SYSCALL_EXIT;
                } else {
                  // The syscall should be blocked
                  registers.orig_rax = -1; // Set the syscall number to an invalid syscall
                  if (ptrace(PTRACE_SETREGS, pid, NULL, &registers) == -1) {
                    perror("Failed to block syscall");
                    return EXIT_FAILURE;
                  }

                  // When it returns, the return value should be altered to indicate that the operation was not permitted, which is the behavior of SYSCALL_BLOCKED above
                  kids[i].next = SYSCALL_BLOCKED;
                }

                // Save the registers in the kids table so that some of them can be changed when the syscall returns, e.g. to alter the return value
                kids[i].registers = registers;
              }
              break;
            }
            break;
          }
        }

        // If the entire kids table was traversed, and this is a newly observed child that we have no spot for in the table, it needs to be killed, since it exceeds the intentionally limited length of the table
        if (too_many_kids) {
          // Someone's gotta go
          if (kill(pid, SIGKILL) == -1) {
            perror("Failed to kill extra child");
            return EXIT_FAILURE;
          }
          continue;
        }
      } else {
        // The child was stopped not because of a syscall, but because of some other signal, which should just be replayed
        if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) == -1) {
          perror("Failed to replay child's signal");
          return EXIT_FAILURE;
        }
        continue;
      }
    }

    // Resume the child while watching for syscalls, unless it has been resumed in some other manner above, in which case this would have been skipped due to the continue statement
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
      perror("Failed to watch for child's syscalls");
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
}
