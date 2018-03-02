#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  //lock_init (&fs_lock); //This line is in the Project2Session.pdf slides
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //thread_exit ();


  /* Currently call thread_exit(); for every case until implemented */
  switch( call_nmbr )
  {
    case SYS_HALT:
      printf ("SYS_HALT system call!\n");
      halt();shutdown_power_off ();
      break;
    case SYS_EXIT:
      printf ("SYS_EXIT system call!\n");
      thread_exit();
      break;
    case SYS_EXEC:
      printf ("SYS_EXEC system call!\n");
      thread_exit();
      break;
    case SYS_WAIT:
      printf ("SYS_WAIT system call!\n");
      thread_exit();
      break;
    case SYS_CREATE:
      printf ("SYS_CREATE system call!\n");
      thread_exit();
      break;
    case SYS_OPEN:
      printf ("SYS_OPEN system call!\n");
      thread_exit();
      break;
    case SYS_FILESIZE:
      printf ("SYS_FILESIZE system call!\n");
      thread_exit();
      break;
    case SYS_WRITE:
      printf ("SYS_WRITE system call!\n");
      thread_exit();
      break;
    case SYS_SEEK:
      printf ("SYS_SEEK system call!\n");
      thread_exit();
      break;
    case SYS_TELL:
      printf ("SYS_TELL system call!\n");
      thread_exit();
      break;
    case SYS_CLOSE:
      printf ("SYS_CLOSE system call!\n");
      thread_exit();
      break;
    default:
      printf ("Unkonwn system call! Exiting...\n");
      thread_exit();
      break;
  }
}


/***************************************************
*   System Call functions
*     - Be sure to update the declaration in 
*        syscall.h if you udpate it here. Most
*        will need to be updated.
***************************************************/

static void halt(void)
{
  shutdown_power_off ();
}

static void exit(void)
{
  
}

static void exec(void)
{
  
}

static void wait(void)
{
  
}

static void create(void)
{
  
}

static void remove(void)
{
  
}

static void open(void)
{
  
}

static void filesize(void)
{
  
}

static void read(void)
{
  
}

static void write(void)
{
  
}

static void seek(void)
{
  
}

static void tell(void)
{
  
}

static void close(void)
{
  
}