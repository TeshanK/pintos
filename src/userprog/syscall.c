#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "lib/kernel/stdio.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
static bool validate_ptr (const void *ptr, size_t size);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static struct file *get_file (int fd);

/* File system lock. */
static struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if (!validate_ptr ((const void *) f->esp, 4))
    thread_exit ();
  
  int syscall_num = *((int *) f->esp);
  if (syscall_num < 1 || syscall_num > SYS_INUMBER)
    thread_exit ();
  
  int *args = (int *) f->esp;
  if (!validate_ptr (args + 1, syscall_num < SYS_EXEC ? 12 : 16))
    thread_exit ();
  
  switch (syscall_num)
    {
    case SYS_HALT: halt (); break;
    case SYS_EXIT: exit (args[1]); break;
    case SYS_EXEC: f->eax = exec ((const char *) args[1]); break;
    case SYS_WAIT: f->eax = wait ((pid_t) args[1]); break;
    case SYS_CREATE: f->eax = create ((const char *) args[1], (unsigned) args[2]); break;
    case SYS_REMOVE: f->eax = remove ((const char *) args[1]); break;
    case SYS_OPEN: f->eax = open ((const char *) args[1]); break;
    case SYS_FILESIZE: f->eax = filesize ((int) args[1]); break;
    case SYS_READ: f->eax = read ((int) args[1], (void *) args[2], (unsigned) args[3]); break;
    case SYS_WRITE: f->eax = write ((int) args[1], (const void *) args[2], (unsigned) args[3]); break;
    case SYS_SEEK: seek ((int) args[1], (unsigned) args[2]); break;
    case SYS_TELL: f->eax = tell ((int) args[1]); break;
    case SYS_CLOSE: close ((int) args[1]); break;
    default: thread_exit ();
    }
}

/* Unified validation for pointers with size check. */
static bool
validate_ptr (const void *ptr, size_t size)
{
  if (!ptr || !is_user_vaddr (ptr))
    return false;
  
  struct thread *t = thread_current ();
  if (!t->pagedir)
    return true;
  
  uint8_t *end = (uint8_t *) ptr + size - 1;
  return is_user_vaddr (end) && 
         pagedir_get_page (t->pagedir, ptr) && 
         (size == 1 || pagedir_get_page (t->pagedir, end));
}

/* Reads a byte at user virtual address UADDR.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Helper to get file pointer from fd with validation. */
static struct file *
get_file (int fd)
{
  if (fd < 0 || fd >= 128)
    return NULL;
  struct thread *cur = thread_current ();
  return cur->files[fd];
}

void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  thread_exit ();
}

pid_t
exec (const char *cmd_line)
{
  if (!cmd_line)
    thread_exit ();
  for (int i = 0; i < 4096; i++)
    {
      if (!validate_ptr (cmd_line + i, 1))
        thread_exit ();
      if (get_user ((const uint8_t *) (cmd_line + i)) == '\0')
        break;
    }
  return process_execute (cmd_line);
}

int
wait (pid_t pid)
{
  return process_wait (pid);
}

bool
create (const char *file, unsigned initial_size)
{
  if (!file || !validate_ptr (file, 1))
    thread_exit ();
  
  lock_acquire (&filesys_lock);
  bool result = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return result;
}

bool
remove (const char *file)
{
  if (!file || !validate_ptr (file, 1))
    thread_exit ();
  
  lock_acquire (&filesys_lock);
  bool result = filesys_remove (file);
  lock_release (&filesys_lock);
  return result;
}

int
open (const char *file)
{
  if (!file || !validate_ptr (file, 1))
    thread_exit ();
  
  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);
  
  if (!f)
    return -1;
  
  struct thread *cur = thread_current ();
  for (int fd = 2; fd < 128; fd++)
    {
      if (!cur->files[fd])
        {
          cur->files[fd] = f;
          cur->next_fd = (fd + 1 < 128) ? fd + 1 : 2;
          return fd;
        }
    }
  
  file_close (f);
  return -1;
}

int
filesize (int fd)
{
  struct file *f = get_file (fd);
  if (!f)
    return -1;
  
  lock_acquire (&filesys_lock);
  int size = file_length (f);
  lock_release (&filesys_lock);
  return size;
}

int
read (int fd, void *buffer, unsigned size)
{
  if (!validate_ptr (buffer, size))
    thread_exit ();
  
  if (fd == 0)
    {
      for (unsigned i = 0; i < size; i++)
        if (!put_user ((uint8_t *) buffer + i, input_getc ()))
          return -1;
      return size;
    }
  
  struct file *f = get_file (fd);
  if (!f)
    return -1;
  
  lock_acquire (&filesys_lock);
  int bytes_read = file_read (f, buffer, size);
  lock_release (&filesys_lock);
  return bytes_read;
}

int
write (int fd, const void *buffer, unsigned size)
{
  if (!validate_ptr (buffer, size))
    thread_exit ();
  
  if (fd == 1)
    {
      putbuf ((const char *) buffer, (size_t) size);
      return size;
    }
  
  struct file *f = get_file (fd);
  if (!f)
    return -1;
  
  lock_acquire (&filesys_lock);
  int bytes_written = file_write (f, buffer, size);
  lock_release (&filesys_lock);
  return bytes_written;
}

void
seek (int fd, unsigned position)
{
  struct file *f = get_file (fd);
  if (!f)
    return;
  
  lock_acquire (&filesys_lock);
  file_seek (f, position);
  lock_release (&filesys_lock);
}

unsigned
tell (int fd)
{
  struct file *f = get_file (fd);
  if (!f)
    return -1;
  
  lock_acquire (&filesys_lock);
  unsigned pos = file_tell (f);
  lock_release (&filesys_lock);
  return pos;
}

void
close (int fd)
{
  struct file *f = get_file (fd);
  if (!f)
    return;
  
  lock_acquire (&filesys_lock);
  file_close (f);
  lock_release (&filesys_lock);
  
  struct thread *cur = thread_current ();
  cur->files[fd] = NULL;
}
