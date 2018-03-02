#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* should these be static in the syscall.c file? */
void halt(void);
void exit(void);
void exec(void);
void wait(void);
void create(void);
void remove(void);
void open(void);
void filesize(void);
void read(void);
void write(void);
void seek(void);
void tell(void);
void close(void);

#endif /* userprog/syscall.h */
