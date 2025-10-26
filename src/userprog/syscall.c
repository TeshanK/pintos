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
static void get_args (struct intr_frame *f, int *argv, int argc);
static bool validate_user_ptr (const void *ptr);
static bool validate_user_string (const char *str);
static bool validate_user_buffer (const void *buffer, size_t size);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

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
  int syscall_num;
  int args[4] = {0, 0, 0, 0};
  
  /* Validate and get syscall number. */
  if (!validate_user_ptr ((const void *) f->esp))
    {
      thread_exit ();
    }
  
  /* Read syscall number byte by byte to avoid segfault. */
  syscall_num = 0;
  for (int j = 0; j < 4; j++)
    {
      int byte = get_user ((const uint8_t *) f->esp + j);
      if (byte == -1)
        {
          thread_exit ();
        }
      syscall_num |= (byte << (j * 8));
    }
  
  /* Get system call arguments. */
  get_args (f, args, 4);
  
  switch (syscall_num)
    {
    case SYS_HALT:
      halt ();
      break;
    case SYS_EXIT:
      exit (args[0]);
      break;
    case SYS_EXEC:
      f->eax = exec ((const char *) args[0]);
      break;
    case SYS_WAIT:
      f->eax = wait ((pid_t) args[0]);
      break;
    case SYS_CREATE:
      f->eax = create ((const char *) args[0], (unsigned) args[1]);
      break;
    case SYS_REMOVE:
      f->eax = remove ((const char *) args[0]);
      break;
    case SYS_OPEN:
      f->eax = open ((const char *) args[0]);
      break;
    case SYS_FILESIZE:
      f->eax = filesize ((int) args[0]);
      break;
    case SYS_READ:
      f->eax = read ((int) args[0], (void *) args[1], (unsigned) args[2]);
      break;
    case SYS_WRITE:
      f->eax = write ((int) args[0], (const void *) args[1], (unsigned) args[2]);
      break;
    case SYS_SEEK:
      seek ((int) args[0], (unsigned) args[1]);
      break;
    case SYS_TELL:
      f->eax = tell ((int) args[0]);
      break;
    case SYS_CLOSE:
      close ((int) args[0]);
      break;
    default:
      thread_exit ();
      break;
    }
}

static void
get_args (struct intr_frame *f, int *argv, int argc)
{
  int *esp = (int *) f->esp;
  
  for (int i = 0; i < argc; i++)
    {
      int *addr = esp + 1 + i;
      if (!validate_user_ptr ((const void *) addr))
        {
          thread_exit ();
        }
      
      /* Read integer byte by byte to avoid segfault. */
      int value = 0;
      for (int j = 0; j < 4; j++)
        {
          int byte = get_user ((const uint8_t *) addr + j);
          if (byte == -1)
            {
              thread_exit ();
            }
          value |= (byte << (j * 8));
        }
      argv[i] = value;
    }
}

static bool
validate_user_ptr (const void *ptr)
{
  if (ptr == NULL)
    return false;
  
  if (!is_user_vaddr (ptr))
    return false;
  
  struct thread *cur = thread_current ();
  if (cur->pagedir != NULL)
    {
      return pagedir_get_page (cur->pagedir, ptr) != NULL;
    }
  
  return true;
}

static bool
validate_user_string (const char *str)
{
  if (!validate_user_ptr (str))
    return false;
  
  /* Check for null terminator within reasonable bounds. */
  for (int i = 0; i < 4096; i++)
    {
      int result;
      if (!validate_user_ptr (str + i))
        return false;
      
      result = get_user ((const uint8_t *) (str + i));
      if (result == -1)
        return false;
      
      if (result == '\0')
        return true;
    }
  
  return false;
}

static bool
validate_user_buffer (const void *buffer, size_t size)
{
  if (buffer == NULL)
    return false;
  
  if (!is_user_vaddr (buffer))
    return false;
  
  if (!is_user_vaddr ((const uint8_t *) buffer + size - 1))
    return false;
  
  struct thread *cur = thread_current ();
  if (cur->pagedir != NULL)
    {
      for (size_t i = 0; i < size; i += PGSIZE)
        {
          if (pagedir_get_page (cur->pagedir, (const uint8_t *) buffer + i) == NULL)
            return false;
        }
    }
  
  return true;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
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
  if (!validate_user_string (cmd_line))
    {
      thread_exit ();
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
  if (!validate_user_string (file))
    {
      thread_exit ();
    }
  
  lock_acquire (&filesys_lock);
  bool result = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  
  return result;
}

bool
remove (const char *file)
{
  if (!validate_user_string (file))
    {
      thread_exit ();
    }
  
  lock_acquire (&filesys_lock);
  bool result = filesys_remove (file);
  lock_release (&filesys_lock);
  
  return result;
}

int
open (const char *file)
{
  if (!validate_user_string (file))
    {
      thread_exit ();
    }
  
  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);
  
  if (f == NULL)
    return -1;
  
  /* Find free fd slot. */
  struct thread *cur = thread_current ();
  for (int fd = 2; fd < 128; fd++)
    {
      if (cur->files[fd] == NULL)
        {
          cur->files[fd] = f;
          return fd;
        }
    }
  
  /* No free slot. */
  file_close (f);
  return -1;
}

int
filesize (int fd)
{
  struct thread *cur = thread_current ();
  
  if (fd == 0 || fd == 1)
    return -1;
  
  if (fd < 0 || fd >= 128 || cur->files[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int size = file_length (cur->files[fd]);
  lock_release (&filesys_lock);
  
  return size;
}

int
read (int fd, void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  
  if (!validate_user_buffer (buffer, size))
    {
      thread_exit ();
    }
  
  if (fd == 0)
    {
      /* Read from stdin. */
      uint8_t *buf = (uint8_t *) buffer;
      for (unsigned i = 0; i < size; i++)
        {
          uint8_t byte = input_getc ();
          if (!put_user (buf + i, byte))
            return -1;
        }
      return size;
    }
  
  if (fd < 0 || fd >= 128 || cur->files[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int bytes_read = file_read (cur->files[fd], buffer, size);
  lock_release (&filesys_lock);
  
  return bytes_read;
}

int
write (int fd, const void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  
  if (!validate_user_buffer (buffer, size))
    {
      thread_exit ();
    }
  
  if (fd == 1)
    {
      /* Write to stdout. */
      putbuf ((const char *) buffer, (size_t) size);
      return size;
    }
  
  if (fd < 0 || fd >= 128 || cur->files[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int bytes_written = file_write (cur->files[fd], buffer, size);
  lock_release (&filesys_lock);
  
  return bytes_written;
}

void
seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();
  
  if (fd < 0 || fd >= 128 || cur->files[fd] == NULL)
    return;
  
  lock_acquire (&filesys_lock);
  file_seek (cur->files[fd], position);
  lock_release (&filesys_lock);
}

unsigned
tell (int fd)
{
  struct thread *cur = thread_current ();
  unsigned pos = 0;
  
  if (fd < 0 || fd >= 128 || cur->files[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  pos = file_tell (cur->files[fd]);
  lock_release (&filesys_lock);
  
  return pos;
}

void
close (int fd)
{
  struct thread *cur = thread_current ();
  
  if (fd < 0 || fd >= 128 || cur->files[fd] == NULL)
    return;
  
  lock_acquire (&filesys_lock);
  file_close (cur->files[fd]);
  cur->files[fd] = NULL;
  lock_release (&filesys_lock);
}
