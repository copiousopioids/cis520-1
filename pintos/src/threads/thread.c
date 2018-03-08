#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Depth limit for donating priority*/
#define DONATION_DEPTH_LIMIT 8

//File descriptor values of 0 and 1 are reserved
#define MIN_FD 2

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of processes in THREAD_BLOCKED state, that is, processes
   that are have been put to sleep for 'x' ticks. */
static struct list sleeping_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

//PROJ 1 ADDED FUNCTIONS

//Comparison functions (to be used in the list_insert_ordered function calls)
static bool thread_tick_compare (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void)
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleeping_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();


}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void)
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Initialize Parent ID to calling thread's ID and add this thread's 
  process tracker to the calling thread's child list */
  t->parent_id = thread_tid();
  struct process_tracker *pt = initialize_process_tracker(t->tid);
  t->pt = pt;
  

  /* Add to run queue. */
  thread_unblock (t);

  /* Replace the current thread if the created thread has a higher priority */
  enum intr_level old_level = intr_disable ();
  max_priority_check();
  intr_set_level (old_level);
  
  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void)
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t)
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

 /* Changed list insertion so that ready threads are ordered by priority
	Old way: list_push_back (&ready_list, &t->elem); */
  list_insert_ordered(&ready_list, &t->elem, (list_less_func *) &thread_priority_compare, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void)
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void)
{
  struct thread *t = running_thread ();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void)
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void)
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread)
    list_insert_ordered(&ready_list, &cur->elem, (list_less_func *) &thread_priority_compare, NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority)
{
  //Disable interrupts
  enum intr_level old_level = intr_disable ();
  
  int old_priority = thread_current()->priority;
  
  //Set the initial priority to the new priority and refresh/update the current priority 
  thread_current()->initial_priority = new_priority;
  refresh_priority ();
  
  // If new priority is greater, donate it
  if (thread_current()->priority > old_priority) priority_donation_with_limit ();
  
  // Else if new priority is less, test if the thread should yield
  else if (thread_current()->priority < old_priority) max_priority_check ();
  
  //Reset interrupt level
  intr_set_level(old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void)
{
  enum intr_level old_level = intr_disable ();
  int p = thread_current()->priority;
  intr_set_level (old_level);

  return p;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED)
{
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void)
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void)
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void)
{
  /* Not yet implemented. */
  return 0;
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux)
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}


/* Returns the running thread. */
struct thread *
running_thread (void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
  
  // Added initializations for priority donation
  t->initial_priority = priority;
  t->wait_on_lock = NULL;
  list_init (&t->donations);

  //Added initializations for syscall file system stuff
  list_init(&t->file_list);
  t->fd = MIN_FD;

}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void)
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();

  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void)
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}


/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/* Comparison function to figure out which thread's wake-up time is sooner */
bool
thread_tick_compare
  (
  const struct list_elem *a,
  const struct list_elem *b,
  void *aux UNUSED
  )
{
  struct thread *thread_a = list_entry(a, struct thread, elem);
  struct thread *thread_b = list_entry(b, struct thread, elem);

  return thread_a->sleeping_ticks < thread_b->sleeping_ticks;
}

/* Comparison function to figure out which thread has a higher priority */
bool
thread_priority_compare
  (
  const struct list_elem *a,
  const struct list_elem *b,
  void *aux UNUSED
  )
{
  struct thread *thread_a = list_entry(a, struct thread, elem);
  struct thread *thread_b = list_entry(b, struct thread, elem);

  return thread_a->priority > thread_b->priority;
}

/*Checks to make sure the current thread does not need to be replaced by another thread (either 
  because there is a thread with higher priority or because the thread has used up its time)*/
void 
max_priority_check (void)
{
  //Make sure the list is not empty
  if (list_empty(&ready_list)) return;
  
  //Get the thread with the highest priority (front of the list)
  struct thread *front_thread = list_entry (list_front(&ready_list), struct thread, elem);

  //If interrupts are on, we can preempt (?) the currently running process if it is warranted
  if (intr_context())
    {
      thread_ticks++;
      if (front_thread->priority > thread_current() -> priority ||
         (thread_ticks >= TIME_SLICE && thread_current()->priority == front_thread->priority))
        {
          intr_yield_on_return();
        }
      return;
    }
	
	//If interrupts are off, and the current thread needs to be replaced just yield
    if (thread_current()->priority < front_thread->priority)
      thread_yield();
}

/* Puts the thread to sleep for a given number of ticks */
void
thread_sleep_until (int64_t ticks)
{
  struct thread *cur = thread_current ();

  ASSERT (!intr_context ());
  //Disable interrupts
  enum intr_level old_level = intr_disable ();
  
  //Put the thread to sleep?
  cur->status = THREAD_BLOCKED;
  
  //Set the wake-up time
  cur->sleeping_ticks = ticks;
  
  // Can't put idle thread to sleep
  if (cur != idle_thread)
    list_insert_ordered(&sleeping_list, &cur->elem, (list_less_func *) &thread_tick_compare, NULL);

  schedule ();
  intr_set_level (old_level);
}

/* Wakes up all sleeping threads whose sleeping_ticks value has
   surpassed the global tick count */
void
try_wake_up_sleeping_threads (int64_t global_ticks)
{
  // While the list is not empty, checks the thread at the front of the list to see if it needs to be woken up
  while (!list_empty(&sleeping_list))
  {
      struct list_elem *front = list_front( &sleeping_list );
      struct thread *t = list_entry( front, struct thread, elem );
	  
      /* Since sleeping_list is ordered by wakeup time, if the front element doesn't 
		 need to be woken up, then none of them do*/
      if ( t->sleeping_ticks > global_ticks ) return;
	  
      /* Must pop from blocked sleeping list before adding thread to the ready list.
		 Otherwise thread.elem will be in 2 lists simultaneously, which isn't allowed.*/
      list_pop_front(&sleeping_list);
      thread_unblock(t);
    }
}

/* Donates the current thread's priority to whatever thread is holding the lock it is waiting on, and
   recurses down the chain until the donation depth limit (currently 8) is reached */
void 
priority_donation_with_limit (void)
{
  //Begin at the current thread
  struct thread *donator = thread_current();
  struct lock *l = donator->wait_on_lock;
  
  //Loop until we reach the depth limit or no lock is being waited on
  for (int depth = 0; l != NULL && depth < DONATION_DEPTH_LIMIT; depth++)
    {
	    //If the lock isn't held, or if the holder's priority is greater then we do nothing
	    if (l->holder == NULL || l->holder->priority >= donator->priority) return;
	
	    //Donate the priority
	    l->holder->priority = donator->priority;
	
	    //Recurse
	    donator = l->holder;
	    l = donator-> wait_on_lock;
    }
}

/* Reset the thread's priority to its initial_priority (necessary when releasing a lock that a process with
   higher priority is waiting on) then check the donations list to see if there are any donated priorities higher
   than initial_priority */
void 
refresh_priority (void)
{
  //Reset the current thread's priority to it's initial priority
  struct thread *t = thread_current();
  t->priority = t->initial_priority;

  //If we have donators available
  if (!list_empty(&t->donations))
    {
	  //Get the donator with highest priority (list should be sorted by highest priority)
      struct thread *donator = list_entry (list_front(&t->donations), struct thread, donation_elem);

	  //If the donator's priority is higher, take it.
      if (donator->priority > t->priority)
        t->priority = donator->priority;
    }
}

/* Removes all the threads waiting on the lock from the list of potential donators */
void 
remove_waiting_donators (struct lock *l)
{
  //Gets the first donator off of the list
  struct list_elem *donator = list_begin(&thread_current()->donations);
  
  //Loop through all the donators in the list
  for (struct list_elem *next; donator != list_end(&thread_current()->donations); donator = next)
    {
		//Get the thread from the list element
	    struct thread *t = list_entry(donator, struct thread, donation_elem);
		
		//Get the next donator before attempting to remove the current one
	    next = list_next(donator);
	
	    //If the thread was waiting on the lock, remove it from the list
	    if(t->wait_on_lock == l) 
		  list_remove(donator);
    }
}

struct process_tracker* initialize_process_tracker(int pid)
{
	struct process_tracker* cp = malloc(sizeof(struct process_tracker));
	cp->pid = pid;
	cp->load = NOT_LOADED;
	cp->exit = cp->wait = false;
	list_push_back(&thread_current()->child_list,
		&cp->elem);
	return cp;
}
