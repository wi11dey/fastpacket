#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define STACK_SIZE (1024 * 1024) // How big of a stack to give the sandboxed process (1 MiB)

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

  // Drop to non-root uid
  setuid(uid);

  // Begin tracing
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);

  // Execute guest.pyc using python3
  execlp("python3", "python3", "guest.pyc", NULL);
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
  waitpid(pid, &status, 0);
  if (WIFEXITED(status)) {
    fprintf(stderr, "Child died before it could be traced");
    return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
  }
  // Trace any additional processes the child spawns, and also take it down with us if we die
  if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK  | PTRACE_O_TRACEVFORK | PTRACE_0_EXITKILL) == -1) {
    perror("Failed to set ptrace options");
    return EXIT_FAILURE;
  }

  
  return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
}
