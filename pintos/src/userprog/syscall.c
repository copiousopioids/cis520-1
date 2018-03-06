#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

//The bottom of the address space.
int MAX_USER_VIRTUAL_ADDR = ((void*) 0x08048000);

int deref_user_pointer_to_kernel(const void *virtualaddr);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  printf ("system call!\n");
  thread_exit ();
}


//See Section 1.5
void verify_valid_ptr (const void *virtualaddr)
{
  //Need to check:
  //null pointer
  //pointer to unmapped virtual memory
  //pointer to kernel virtual address space
  if (virtualaddr < MAX_USER_VIRTUAL_ADDR || !is_user_vaddr(virtualaddr))
    //terminate and free resources.
    thread_exit();
}

//Dereference a valid user pointer
int deref_user_pointer_to_kernel(const void *virtualaddr)
{
  // bytes within range are correct
  // for strings + buffers?
  check_valid_ptr(virtualaddr);
  void *usrptr = pagedir_get_page(thread_current()->pagedir, virtualaddr);
  if (!usrptr)
      exit(ERROR);
  return (int) usrptr;
}
