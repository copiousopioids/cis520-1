#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"

struct cmd_line
{
	char *file_name;
	char *arguments;
};

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

void syscall_init (void);
void close_all_files( void );
struct process_tracker* pid_lookup(int pid); 
void exit(int status);
void add_cline_to_kernel(void* cline_);
struct cmd_line * get_cline_to_kernel(void);

#endif /* userprog/syscall.h */
