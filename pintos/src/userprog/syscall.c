#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h" 
#include "threads/vaddr.h"

#define ARG_LIMIT 3
#define USER_VADDR_START ((void *) 0x08048000) // Defined in section 1.4.1 of Project Doc
#define ERROR -1
#define WORD_SIZE sizeof(char *)

/* Helpers */
static struct file_binder* fd_lookup(int fd);

static void syscall_handler(struct intr_frame *);
static void verify_valid_ptr(const void *vaddr);
static void get_arguments(struct intr_frame *f, int *arg, int num_args);
static void verify_valid_buffer(void* buffer, unsigned size); 

static void halt(void);
//static void exit(int status);
static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

int deref_user_pointer_to_kernel(const void *virtualaddr);

//Lock for file system calls
static struct lock fs_lock;

//cmd_line cline to save in kernel space
static struct cmd_line cline;

/* Thing for binding a file descriptor handle to a file. */
struct file_binder
{
	struct list_elem elem;      /* List element. */
	struct file *file;          /* File. */
	int fd;						/* File descriptor handle. */
};

void
syscall_init(void)
{
	lock_init(&fs_lock); //This line is in the Project2Session.pdf slides
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
	int args[ARG_LIMIT];
	
	verify_valid_ptr((const void*)f->esp + 0);
	verify_valid_ptr((const void*)f->esp + 1);
	verify_valid_ptr((const void*)f->esp + 2);
	verify_valid_ptr((const void*)f->esp + 3);

	//verify_valid_buffer( f->esp, sizeof(uint32_t));
	uint32_t call_nmbr = (*(uint32_t *)f->esp);
	
	switch (call_nmbr)
	{
	case SYS_HALT:    /* (void) 0 args */
		//printf("SYS_HALT system call!\n");
		halt();
		break;

	case SYS_EXIT:    /* (int status) 1 arg */
		//printf("SYS_EXIT system call!\n");
		get_arguments(f, &args[0], 1);
		exit(args[0]);
		break;

	case SYS_EXEC:    /* (const char *cmd_line) 1 arg */
		//printf("SYS_EXEC system call!\n");
		get_arguments(f, &args[0], 1);
		args[0] = deref_user_pointer_to_kernel((const void *)args[0]);
		f->eax = exec((const char *)args[0]);
		break;

	case SYS_WAIT:    /* (pid_t pid) 1 arg */
		//printf("SYS_WAIT system call!\n");
		get_arguments(f, &args[0], 1);
		f->eax = wait(args[0]);
		break;

	case SYS_CREATE:  /* (const char *file, unsigned initial_size) 2 args */
		//printf("SYS_CREATE system call!\n");
		get_arguments(f, &args[0], 2);
		args[0] = deref_user_pointer_to_kernel((const void *)args[0]);
		f->eax = create((const char *)args[0], (unsigned)args[1]);
		break;

	case SYS_REMOVE: /* (const char *file) 1 args */
		//printf("SYS_REMOVE system call!\n");
		get_arguments(f, &args[0], 1);
		args[0] = deref_user_pointer_to_kernel((const void *)args[0]);
		f->eax = remove((const char *)args[0]); //Change from create() to remove()
		break;

	case SYS_OPEN:    /* const char *file) 1 arg */
		//printf("SYS_OPEN system call!\n");
		get_arguments(f, &args[0], 1);
		args[0] = deref_user_pointer_to_kernel((const void *)args[0]);
		f->eax = open((const char *)args[0]);
		break;

	case SYS_FILESIZE:/* (int fd) 1 arg */
		//printf("SYS_FILESIZE system call!\n");
		get_arguments(f, &args[0], 1);
		f->eax = filesize(args[0]);
		break;

	case SYS_READ:   /* (int fd, void *buffer, unsigned size) 3 args */
		//printf("SYS_READ system call!\n");
		get_arguments(f, &args[0], 3);
		verify_valid_buffer((void *)args[1], (unsigned)args[2]);
		args[1] = deref_user_pointer_to_kernel((const void *)args[1]);
		f->eax = read(args[0], (void *)args[1], (unsigned)args[2]);
		break;

	case SYS_WRITE:   /* (int fd, void *buffer, unsigned size) 3 args */
		//printf("SYS_WRITE system call!\n");
		get_arguments(f, &args[0], 3);
		verify_valid_buffer((void *)args[1], (unsigned)args[2]);
		args[1] = deref_user_pointer_to_kernel((const void *)args[1]);
		f->eax = write(args[0], (const void *)args[1], (unsigned)args[2]);
		break;

	case SYS_SEEK:    /* (int fd, unsigned position) 2 args */
		//printf("SYS_SEEK system call!\n");
		get_arguments(f, &args[0], 2);
		seek(args[0], (unsigned)args[1]);
		break;

	case SYS_TELL:    /* (int fd) 1 args */
		//printf("SYS_TELL system call!\n");
		get_arguments(f, &args[0], 1);
		f->eax = tell(args[0]);
		break;

	case SYS_CLOSE:   /* (int fd)  1 arg */
		//printf("SYS_CLOSE system call!\n");
		get_arguments(f, &args[0], 1);
		close(args[0]);
		break;

	default:          /* default case */
		//printf("Unkonwn system call! Exiting...\n");
		exit(ERROR); //TODO: exit differently with error code for debugging?
		break;
	}
}


/* Takes a virtual address pointer and verifies that it is within that
processe's provided virtual adderss space. */
//See Section 1.5
void verify_valid_ptr(const void *virtualaddr)
{
	//Need to check:
	//null pointer
	//pointer to unmapped virtual memory
	//pointer to kernel virtual address space

	//If pointer is null or outside user address space
	if (virtualaddr == NULL || !is_user_vaddr(virtualaddr) || virtualaddr < USER_VADDR_START)
		exit(ERROR);//terminate and free resources.

}


//Dereference a valid user pointer
int deref_user_pointer_to_kernel(const void *virtualaddr)
{
	// bytes within range are correct
	// for strings + buffers?
	verify_valid_ptr(virtualaddr);
	void *usrptr = pagedir_get_page(thread_current()->pagedir, virtualaddr);
	if (!usrptr) exit(ERROR);

	return (int)usrptr;
}


/* Takes a pointer to a stack frame and gets 'num_args' arguments from
it to execute the system call */
static void
get_arguments(struct intr_frame *f, int *arg, int num_args)
{
	int *next_arg;
	for (int i = 0; i < num_args; i++)
	{
		// get next arg address off the stack ( i + 1 becuase i starts at 0)
		next_arg = (int *)f->esp + i + 1;
		// validate this address
		verify_valid_ptr((const void *)next_arg);
		// save in it in the buffer
		arg[i] = *next_arg;
	}
}

static void 
verify_valid_buffer(void* buffer, unsigned size)
{
	char* local_buffer = (char *)buffer;
	for (unsigned i = 0; i < size; i++)
	{
		verify_valid_ptr((const void*)local_buffer);
		local_buffer++;
	}
}

/* Copy the cmd_line into kernel memory so that 'all' processes/threads can
	access their aruments (needed for exec) */
void add_cline_to_kernel(void* cline_)
{
  cline.file_name = ((struct cmd_line *)cline_)->file_name;
  cline.arguments = ((struct cmd_line *)cline_)->arguments;
}

/* get the cmd_line from the kernel memory space (needed for exec) */
struct cmd_line * get_cline_to_kernel(void)
{
	return &cline;
}

/***************************************************
*   System Call functions
***************************************************/
static void
halt(void)
{
	shutdown_power_off();
}

void
exit(int status)
{
	struct thread *t = thread_current();

	/*If the parent process is still alive then update the process tracker
	so that it can find the exit status */
	if (thread_alive(t->parent_id)) t->pt->exit_status = status;

	t->pt->exit = true; //FIX?: Added this line to show that (child) thread has called exit
	//Process termination message. Thread name is set in process_execute
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

static pid_t
exec(const char *cmd_line)
{
	//Begin execution of a child process
	pid_t pid = process_execute(cmd_line);

	//Get the child's process tracker to see if it has loaded
	struct process_tracker* pt = pid_lookup(pid);

	ASSERT(pt);
	
	//Wait until the process is loaded
	while (pt->load == NOT_LOADED) {
	  barrier();
	  //printf("inside while\n");
	}

	//If loading fails something went wrong
	if (pt->load == LOAD_FAILED) 
	  return ERROR; 

	//Reaching this means everything is good to go!
	return pid;
}

static int
wait(pid_t pid)
{
	return process_wait(pid);
}

static bool
create(const char *file, unsigned initial_size)
{
	lock_acquire(&fs_lock);
	bool success = filesys_create(file, initial_size); 
	lock_release(&fs_lock);
	return success;
}

static bool
remove(const char *file)
{
	lock_acquire(&fs_lock);
	bool success = filesys_remove(file);
	lock_release(&fs_lock);
	return success;
}

/* Different functions from file.c return off_t, but pretty sure int should work. More here:
http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_types.h.html,
https://www.gnu.org/software/libc/manual/html_node/File-Position-Primitive.html */

static int
open(const char *file)
{
	int fd = ERROR;
	lock_acquire(&fs_lock);
	struct file *f = filesys_open(file);
	//If the file opens
	if (f)
	{
		//Bind the file handler to the file and add the file_binder to the threads list
		struct file_binder *fb = malloc(sizeof(struct file_binder));
		fb->file = f;
		fd = fb->fd = thread_current()->next_handle++;
		list_push_back(&thread_current()->file_list, &fb->elem);
	}

	lock_release(&fs_lock);
	return fd;
}

static int
filesize(int fd)
{
	int size = ERROR;

	lock_acquire(&fs_lock);
	struct file_binder* fb = fd_lookup(fd);
	if (fb)
	{
		size = file_length(fb->file);
	}
	lock_release(&fs_lock);

	return size;
}

static int
read(int fd, void *buffer, unsigned size)
{
	int bytes_read = ERROR;
	//If reading from console
	if (fd == 0)
	{
		uint8_t* loc_buf = (uint8_t *)buffer;
		for (unsigned i = 0; i < size; i++)
		{
			loc_buf[i] = input_getc();
		}
		bytes_read = size;
	}
	else
	{
		lock_acquire(&fs_lock);
		struct file_binder *fb = fd_lookup(fd);
		if (fb)
		{
			bytes_read = file_read(fb->file, buffer, size);
		}
		lock_release(&fs_lock);
	}
	return bytes_read;
}

static int
write(int fd, const void *buffer, unsigned size)
{
	int bytes_written = ERROR;

	if (fd == 1)
	{
		putbuf(buffer, size);
		bytes_written = size;
	}
	else
	{
		lock_acquire(&fs_lock);
		struct file_binder* fb = fd_lookup(fd);
		if (fb)
		{
			bytes_written = file_write(fb->file, buffer, size);
		}
		lock_release(&fs_lock);
	}
	return bytes_written;
}

static void
seek(int fd, unsigned position)
{
	lock_acquire(&fs_lock);
	struct file_binder* fb = fd_lookup(fd);
	if (fb)
	{
		file_seek(fb->file, position);
	}
	lock_release(&fs_lock);
}

static unsigned
tell(int fd)
{
	int offset = ERROR;

	lock_acquire(&fs_lock);
	struct file_binder* fb = fd_lookup(fd);
	if (fb)
	{
		offset = file_tell(fb->file);
	}
	lock_release(&fs_lock);

	return offset;
}

static void
close(int fd)
{
	lock_acquire(&fs_lock);
	struct file_binder* fb = fd_lookup(fd);
	if (fb)
	{
		file_close(fb->file);
		list_remove(&fb->elem);
	}
	lock_release(&fs_lock); 
}


/* Helpers */

/* Returns the file_binder associated with the given fd or NULL if there is none */
struct file_binder* 
fd_lookup(int fd)
{
	struct thread *cur = thread_current();
	struct list_elem *e;
	struct file_binder *fb;

	for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
	{
		fb = list_entry(e, struct file_binder, elem);
		if (fd == fb->fd)
		{
			return fb;
		}
	}
	return NULL;
}

void 
close_all_files( void )
{
	lock_acquire(&fs_lock);
	struct thread *cur = thread_current();
	struct list_elem *e;
	struct file_binder *fb;

	for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
	{
		fb = list_entry(e, struct file_binder, elem);
		file_close(fb->file);
		list_remove(&fb->elem);
		//free(fb);???
	}
	lock_release(&fs_lock);
}

struct process_tracker* 
pid_lookup(int pid) 
{
	struct thread *cur = thread_current();
	struct list_elem *e;
	struct process_tracker *pt;

	for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e))
	{
		pt = list_entry(e, struct process_tracker, elem);
		if (pid == pt->pid) return pt;
	}
	return NULL;
}
