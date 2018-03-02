#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define ARG_LIMIT 3
#define USER_VADDR_START ((void *) 0x08048000) // Defined in section 1.4.1 of Project Doc

static void syscall_handler (struct intr_frame *);
static void check_valid_access (const void *vaddr);
static void get_arguments (struct intr_frame *f, int *arg, int num_args);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  //lock_init (&fs_lock); //This line is in the Project2Session.pdf slides
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[ARG_LIMIT];
  uint32_t call_nmbr;
  //printf ("system call!\n");
  //thread_exit ();

  check_valid_access( (const void*) f->esp );
  call_nmbr = ( *(uint32_t *)f->esp );

  /* Currently call thread_exit(); for every case until implemented */
  switch( call_nmbr )
  {
    case SYS_HALT:    /* (void) 0 args */
      printf ("SYS_HALT system call!\n");
      halt();shutdown_power_off ();
      break;
    case SYS_EXIT:    /* (int status) 1 arg */
      printf ("SYS_EXIT system call!\n");
      get_arguments( f, &args, 1 ); // Do I need address of the first element instead?? *args[0]
      thread_exit();
      break;
    case SYS_EXEC:    /* (const char *cmd_line) 1 arg */
      printf ("SYS_EXEC system call!\n");
      get_arguments( f, &args, 1 );
      thread_exit();
      break;
    case SYS_WAIT:    /* (pid_t pid) 1 arg */
      printf ("SYS_WAIT system call!\n");
      get_arguments( f, &args, 1 );
      thread_exit();
      break;
    case SYS_CREATE:  /* (const char *file, unsigned initial_size) 2 args */
      printf ("SYS_CREATE system call!\n");
      get_arguments( f, &args, 2) ;
      thread_exit();
      break;
    case SYS_OPEN:    /* const char *file) 1 arg */
      printf ("SYS_OPEN system call!\n");
      get_arguments( f, &args, 1 );
      thread_exit();
      break;
    case SYS_FILESIZE:/* (int fd) 1 arg */
      printf ("SYS_FILESIZE system call!\n");
      get_arguments( f, &args, 1 );
      thread_exit();
      break;
    case SYS_READ:   /* (int fd, void *buffer, unsigned size) 3 args */
      printf ("SYS_WRITE system call!\n");
      get_arguments( f, &args, 3 );
      thread_exit();
      break;
    case SYS_WRITE:   /* (int fd, void *buffer, unsigned size) 3 args */
      printf ("SYS_WRITE system call!\n");
      get_arguments( f, &args, 3 );
      thread_exit();
      break;
    case SYS_SEEK:    /* (int fd, unsigned position) 2 args */
      printf ("SYS_SEEK system call!\n");
      get_arguments( f, &args, 2 );
      thread_exit();
      break;
    case SYS_TELL:    /* (int fd) 1 args */
      printf ("SYS_TELL system call!\n");
      get_arguments( f, &args, 1 );
      thread_exit();
      break;
    case SYS_CLOSE:   /* (int fd)  1 arg */
      printf ("SYS_CLOSE system call!\n");
      get_arguments( f, &args, 1 );
      thread_exit();
      break;
    default:          /* default case */
      printf ("Unkonwn system call! Exiting...\n");
      thread_exit(); //TODO: exit differently with error code for debugging?
      break;
  }
}

/* Takes a virtual address pointer and verifies that it is within that 
    processe's provided virtual adderss space. */
static void
check_valid_access ( const void *vaddr )
{
  //Verify that 
  if( !is_user_vaddr(vaddr) || vaddr < USER_VADDR_START )
    {
      printf ("Bad access! Exiting...\n");
      thread_exit(); //TODO: exit differently with error code for debugging?
    }
}


/* Takes a pointer to a stack frame and gets 'num_args' arguments from
    it to execute the system call */
static void 
get_arguments ( struct intr_frame *f, int *arg, int num_args ) 
{
  int *next_arg;
  for( int i = 0; i < num_args; i++ )
    {
      // get next arg address off the stack ( i + 1 becuase i starts at 0)
      next_arg = (int *) f->esp + i + 1;
      // validate this address
      check_valid_access( (const void *) next_arg );
      // save in it in the buffer
      arg[i] = *next_arg;
    }
}

/***************************************************
*   System Call functions
*     - Be sure to update the declaration in 
*        syscall.h if you udpate it here. Most
*        will need to be updated.
***************************************************/
 
void
halt( void )
{
  shutdown_power_off ();
}

void
exit(int status )
{
  
}

pid_t
exec( const char *cmd_line )
{
  
}

int
wait( pid_t pid )
{
  
}

bool
create( const char *file, unsigned initial_size )
{
  
}

bool
remove( const char *file )
{
  
}

int
open( const char *file )
{
  
}

int
filesize( int fd )
{
  
}

int
read( int fd, void *buffer, unsigned size )
{
  
}

int
write( int fd, const void *buffer, unsigned size )
{
  
}

void
seek( int fd, unsigned position )
{
  
}

unsigned
tell( int fd )
{
  
}

void
close( int fd )
{
  
}