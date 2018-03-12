#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h" //FIX?: added to for barrier() call 
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;


/*
For Argument Passing, I used these repositories as inspiration

Getting and idea of where to start/go
https://github.com/codyjack/OS-pintos 

Got stuck on setting up stack and found this which gave me the idea to make the argv array
https://github.com/pindexis/pintos-project2 

*/

//Used in load, values are arbitrary
#define CMD_ARGS_MAX 30
//#define CMD_LENGTH_MAX 100
#define ERROR -1

//Added an arguments parameter for the load function
static bool load (const char *cmdline, void (**eip) (void), void **esp, char **arguments);

//Function for taking apart the arguments and forming argv
static int get_args(char* file_name, char** arguments, char* argv[]);

struct cmd_line
{
	char *file_name;
	char *arguments;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  //Split the input line into the filename and arguments - Need to do this so we can use the filename when 
  //starting the thread, otherwise it would be easier to split it in start_process
  struct cmd_line cline;
  char *save_ptr;
  cline.file_name = strtok_r(fn_copy, " ", &save_ptr);
  cline.arguments = save_ptr;

  // Create a new thread to execute the command line
  tid = thread_create (cline.file_name, PRI_DEFAULT, start_process, &cline);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmd_line_)
{
  //Convert the argument to a cmd_line from a void
  struct cmd_line *cline = cmd_line_;

  struct intr_frame if_;
  bool success;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  //Load the executable using the arguments
  success = load (cline->file_name, &if_.eip, &if_.esp, &(cline->arguments));

  if (success) thread_current()->pt->load = LOADED;
  else thread_current()->pt->load = LOAD_FAILED;

  /* If load failed, quit. */
  //palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
	struct process_tracker* pt = pid_lookup(child_tid); //FIX?: remove pointer (*)

	/* Make sure process tracker exists and its not already waiting */
	if (!pt || pt->wait) //FIX?: cp -> pt? cd does not exist
    return ERROR; 

	/* Set the waiting status to true and wait until the process has exited */
	pt->wait = true;
	while (!pt->exit) 
    barrier();

	//Get the status, free the child and return the status
	int status = pt->exit_status; //FIX?: pt->status to pt->exit_status? status does not exist
	list_remove(&pt->elem);
	free(pt); 

	return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  //Close all the files opened by the process
  close_all_files();

  //Free all the children
  struct list_elem *e;
  struct process_tracker *pt;
  for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e))
  {
	  pt = list_entry(e, struct process_tracker, elem);
	  list_remove(&pt->elem);
	  free(pt);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

//Used in stack setup, Pintos is x86 so words should be 4 bytes
#define WORD_SIZE sizeof(char *)


//Added file name and arguments parameters to the stack setup function
//static bool setup_stack(void **esp, char** argv, int argc);
static bool setup_stack (void **esp, const char *file_name);

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp, char **arguments) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  //Create argv
  //char *argv[CMD_ARGS_MAX];
  //int argc =  get_args(file_name, arguments, argv);

  //Set up the stack using argv
  //if (!setup_stack (esp, argv, argc))
  if(!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *file_name)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) 
        {
  	      *esp = PHYS_BASE;

          uint8_t *argstr_head;
          char *cmd_name = thread_current ()->name;
          int strlength, total_length = 0;
          int argc = 0;

          /*push the arguments string into stack*/
          strlength = strlen(file_name) + 1;
          *esp -= strlength;
          memcpy(*esp, file_name, strlength);
          total_length += strlength;

          /*push command name into stack*/
          strlength = strlen(cmd_name) + 1;
          *esp -= strlength;
          argstr_head = *esp;
          memcpy(*esp, cmd_name, strlength);
          total_length += strlength;

          /*set alignment, get the starting address, modify *esp */
          *esp -= 4 - total_length % 4;

          /* push argv[argc] null into the stack */
          *esp -= 4;
          * (uint32_t *) *esp = (uint32_t) NULL;

          /* scan throught the file name with arguments string downward,
           * using the cur_addr and total_length above to define boundary.
           * omitting the beginning space or '\0', but for every encounter
           * after, push the last non-space-and-'\0' address, which is current
           * address minus 1, as one of argv to the stack, and set the space to
           * '\0', multiple adjancent spaces and '0' is treated as one.
           */
          int i = total_length - 1;
          /*omitting the starting space and '\0' */
          while (*(argstr_head + i) == ' ' ||  *(argstr_head + i) == '\0')
            {
              if (*(argstr_head + i) == ' ')
                {
                  *(argstr_head + i) = '\0';
                }
              i--;
            }

          /*scan through args string, push args address into stack*/
          char *mark;
          for (mark = (char *)(argstr_head + i); i > 0;
                i--, mark = (char*)(argstr_head+i))
            {
              /*detect args, if found, push it's address to stack*/
              if ( (*mark == '\0' || *mark == ' ') &&
                   (*(mark+1) != '\0' && *(mark+1) != ' '))
                {
                  *esp -= 4;
                  * (uint32_t *) *esp = (uint32_t) mark + 1;
                  argc++;
                }
              /*set space to '\0', so that each arg string will terminate*/
              if (*mark == ' ')
                *mark = '\0';
            }

          /*push one more arg, which is the command name, into stack*/
          *esp -= 4;
          * (uint32_t *) *esp = (uint32_t) argstr_head;
          argc++;

          /*push argv*/
          * (uint32_t *) (*esp - 4) = *(uint32_t *) esp;
          *esp -= 4;

          /*push argc*/
          *esp -= 4;
          * (int *) *esp = argc;

          /*push return address*/
          *esp -= 4;
          * (uint32_t *) *esp = 0x0;
        } 
      else
        palloc_free_page (kpage);
    }

  return success;
}


#if 0
/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char** argv, int argc) 
{
  uint8_t *kpage;
  bool success = false;
  char **args;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
	    if (success)
	      {
		      *esp = PHYS_BASE;

		      //Keep an array of pointers to the addresses where argv get stored
		      char * argpointers[argc+1];

		      //Push argv entries to the stack in reverse order, saving the address where each entry is stored
		      for (int i = argc - 1; i >= 0; i--) 
		        {
			        *esp -= (strlen(argv[i]) + 1) * sizeof(char);
			        argpointers[i] = *esp;
			        memcpy(*esp, argv[i], strlen(argv[i]) + 1);
		        }

		      //Align the stack and set up the sentinel
		      argpointers[argc] = 0;
		      int i = (size_t)*esp % WORD_SIZE;
		      if (i != 0) 
		        {
			        *esp -= i;
			        memcpy(*esp, &argv[argc], i);
		        }

		      //Push the sentinel and all the adresses of argv entries
		      for (i = argc; i >= 0; i--)
		        {
			        *esp -= WORD_SIZE;
			        memcpy(*esp, &argpointers[i], WORD_SIZE);
		        }

		      /* Method 1 of pushing argv to stack - 99% sure it works */
		      //Save the current esp (address of argv[0])
		      char *old = *esp;
		      //Push argv (address of argv[0])
		      *esp -= WORD_SIZE;
		      memcpy(*esp, &old, WORD_SIZE);
		  

		      /* Method 2 of pushing argv to stack - cleaner, but only 87% sure it works
		      //Push argv (address of argv[0])
		      *esp -= WORD_SIZE;
		      memcpy(*esp, &(*esp+WORD_SIZE), WORD_SIZE);
		      */
        
		      /*Push argc - move esp by WORD_SIZE to keep return address aligned, but only copy the size of the int. It
			        shouldn't matter, since with 32/64 bit machines sizeof(int)==sizeof(char *) but just to be safe */
		      *esp -= WORD_SIZE;
		      memcpy(*esp, &argpointers, sizeof(int));
        
		      //Push fake return address
		      *esp -= WORD_SIZE;
		      memcpy(*esp, &argpointers[argc], sizeof(int));
	      }
      
      else
		    palloc_free_page(kpage);
	  }

  return success;
}
#endif

//Adapted from https://github.com/pindexis/pintos-project2/blob/master/userprog/process.c (Function originally called 'extract_command_args')
static int
get_args(char* file_name, char** arguments, char* argv[])
{
	argv[0] = file_name;
	char *token;
	int argc = 1;
	while ((token = strtok_r(NULL, " ", arguments)) != NULL)
	{
		argv[argc++] = token;
	}
	return argc;
}



/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
