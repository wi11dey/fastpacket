#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define STACK_SIZE (1024 * 1024) // How big of a stack to give the sandboxed process (1 MiB)

static char stack[STACK_SIZE]; // Child stack goes in bss segment

int sandbox(void* argv) {
  // argv is guaranteed to be of length 3 because the check has been done in main
  char* guest_dir = ((char**) argv)[1];
  int uid = atoi(((char**) argv)[2]);

  // Change working directory to guest_dir
  if (chdir(guest_dir)) {
    perror("Sandbox failed to change directory");
    return EXIT_FAILURE;
  }

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

  sleep(1); // Sleep for a section to ensure that the child process has been created before we wait on it
  waitpid(pid, NULL, 0);
  return EXIT_SUCCESS; // Return success even if the child does not, because at least the sandboxer has done its job
}
