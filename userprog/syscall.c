#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"

#define USER_B_ADDR ((void *) 0x08048000)

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer_, unsigned size);
int write (int fd, void *buffer_, unsigned size);
void seek (int fd, unsigned position);
int tell (int fd);
void close (int fd);

static inline 
bool perform_cpy(uint8_t *write_buffer,const uint8_t *read_buffer);
static void * fetch_arg (void **,int);
int u_k_ptr(const void *u_k_ptr);
void verify_valid_ptr(const void *ptr_addr);
static struct lock file_lock;
static void syscall_handler (struct intr_frame *);

/* file descriptor structure */
struct file_descriptor
  {
    struct list_elem elem;      // List element
    struct file *file;          // File
    int id;                 	// File id
  };

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{

	//verify the validity of the pointer
	verify_valid_ptr((const void*)f->esp);
	//get the syscall number
    int sys_call_num = *(int *)f->esp;
	int status;
	const char* ufile;
	pid_t pidt;
	//pid_t pidt;
	const char* file;
	unsigned size ;
	int fsize;
	int fd1 ;
	void* buf;
	int arg1;
	unsigned* arg2;
	int arg3;
	
    switch(sys_call_num) {
      case SYS_HALT:
        halt();
        NOT_REACHED();
      case SYS_EXIT:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		status = *(int *)fetch_arg(&(f->esp), 4);
        exit(status);
        NOT_REACHED();
      case SYS_EXEC:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		ufile=*(const char **)fetch_arg(&(f->esp) ,4);
		arg3= u_k_ptr((const void *) ufile);
		f->eax = (pid_t) exec((const char *)ufile);
        break;
      case SYS_WAIT:
	    verify_valid_ptr((const void*)fetch_arg(&(f->esp), 4));
		pidt = *(pid_t *)fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) wait(pidt);
        break;
      case SYS_CREATE:
	  //16
		file = *(const char **) fetch_arg(&(f->esp), 16);
		size = *(unsigned *) fetch_arg (&(f->esp), 20);
		arg3= u_k_ptr((const void *) file);
		f->eax = (uint32_t)create ((const char *)file, size);
        break;
      case SYS_REMOVE:
		file = *(const char **) fetch_arg(&(f->esp), 4);
		arg3= u_k_ptr((const void *) file);
        f->eax = (uint32_t) remove((const char *)file);
        break;
      case SYS_OPEN:
		file = *(const char **) fetch_arg(&(f->esp), 4);
		arg3= u_k_ptr((const void *) file);
        f->eax = (uint32_t) open((const char *)file);
        break;	
      case SYS_FILESIZE:
		fsize = *(int *)fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) filesize(fsize);
        break;
      case SYS_READ:
		fd1 = *(int *)fetch_arg(&(f->esp), 20);
		buf = *(void **) fetch_arg(&(f->esp), 24);
		size = *(unsigned *) fetch_arg (&(f->esp), 28);
		arg3= u_k_ptr((const void *) buf);
        f->eax = (uint32_t) read(fd1,(const void *)buf,size);
        break;
      case SYS_WRITE:
		fd1 = *(int *)fetch_arg(&(f->esp), 20);
		buf = *(void **) fetch_arg(&(f->esp), 24);
		size = *(unsigned *) fetch_arg (&(f->esp), 28);
		arg3= u_k_ptr((const void *) buf);
        f->eax = (uint32_t) write(fd1,(const void *)buf,size);
        break;
      case SYS_SEEK:
		arg1 =*(int *)fetch_arg(&(f->esp), 16);
		arg2 = *(unsigned *) fetch_arg (&(f->esp), 20);
        seek(arg1,arg2);
        break;
      case SYS_TELL:
		arg1 =*(int *)fetch_arg(&(f->esp), 4);
        f->eax = (uint32_t) tell(arg1);
        break;
      case SYS_CLOSE:
		arg1 =*(int *)fetch_arg(&(f->esp), 4);
        close(arg1);
        break;
      default:
        printf("This system call is not implemented!");
        thread_exit();
        break;
	}
}

/* --------------- Helper functions for the system calls -----------*/

//----------------------------------------------------------------------
/* check for the valid pointer by check the pointer address is less 
   than the user bottom address and is user's address valid */
	void verify_valid_ptr(const void *ptr_addr)
	{
		if(ptr_addr < USER_B_ADDR || !is_user_vaddr(ptr_addr))
		{
			exit(-1);
		}
	}
	
/* check if the current bytes are correct and in the valid range for all buffer
	and strings */	
int u_k_ptr(const void *u_k_ptr)
{
	verify_valid_ptr(u_k_ptr);
	struct thread *cur=thread_current();
	void *p=pagedir_get_page(cur->pagedir,u_k_ptr);
	if(!p)
	{
		exit(-1);
	}
	return (int)p;
}

/* return argument at the calculated stack address i.e the
   esp pointer + offset*/
static void *
fetch_arg (void **esp, int offset)
{
	return (void *)(*esp + offset);
} 

/* this function will return true if the uaddr is vaild address*/
static bool
validate (const void *user_address )
{
	struct thread *cur=thread_current();
	return (user_address < PHYS_BASE &&	pagedir_get_page 
					(cur->pagedir, user_address) != NULL);
}

/* copy a single byte at a time from the user address and the kernel
	address also return false if the user address is not valid and
	return true if the copy is successful*/
	
	static inline bool
	perform_cpy (uint8_t *write_buffer, const uint8_t *read_buffer)
	{
	  size_t size_one=1;
	  uint8_t *write_buf=write_buffer;
	  const uint8_t *read_buf=read_buffer;
	  if(!is_user_vaddr(read_buffer))
	  {
		return false;
	  }
	  else
	  {
		memcpy(write_buf,read_buf,size_one);
		return true;
	  }
	  
	} 

/* writes the given byte to user address also it returns false if the
	user address is not valid.Returns true if the copy is successful*/
	static inline bool
	put_user (uint8_t *write_buffer, uint8_t byte)
	{
	 /*  int result;
	  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
		   : "=m" (*write_buffer), "=&a" (result) : "q" (byte));
	  return result != 0; */
	  
	  size_t size_one=1;
	  uint8_t *write_buf=write_buffer;
	  const uint8_t *read_buf=byte;
	  if(!is_user_vaddr(byte))
	  {
		return false;
	  }
	  else
	  {
		memcpy(write_buf,read_buf,size_one);
		return true;
	  }
	  
	  
	}	

/* this function will copy the user string to the kernel memory.
	if the user access is not valid then thread_exit.This function
	returns the page that which has to be freed*/	
	
	static char *
	take_in_km (const char *buff) 
	{
	  char *cpy_buff;
	  size_t len;
	  cpy_buff = palloc_get_page (0);
	  int c=0;
	  if (cpy_buff == NULL) 
		thread_exit ();
	  len=0;
		while(len<PGSIZE)
		{
			c++;
			if (buff >= (char *) PHYS_BASE || 
			!perform_cpy (cpy_buff + len, buff++)) 
				{
				  palloc_free_page (cpy_buff);
				  thread_exit (); 
				}   
			  if (cpy_buff[len] == '\0')
				return cpy_buff;
			len++;
		}
	  //assgin the last place to null	
	  cpy_buff[PGSIZE - 1] = '\0';
	  return cpy_buff;
	}
	
/*this function will iterate through the list of file descriptors of the
  current thread and terminates if the fd is not associated with the
  current thread i.e the current open file*/
  
	static struct file_descriptor *
	get_file_desc (int fd) 
	{
	  struct thread *cur = thread_current ();
	  struct list_elem *ele;
	   
	  for (ele = list_begin (&cur->file_descs);
		   ele != list_end (&cur->file_descs);
		   ele = list_next (ele))
		{
		  struct file_descriptor *f_d;
		  f_d = list_entry (ele, struct file_descriptor, elem);
		  if (f_d->id == fd)
			return f_d;
		}
	  thread_exit ();
	} 


/* ------------------------ system calls ---------------------------*/
//----------------------------------------------------------------------

/* Halt system call. */
//----------------------------------------------------------------------

	void halt (void)
	{
	  shutdown_power_off ();
	}

/* Exit system call. */
//----------------------------------------------------------------------

	void exit (int status) 
	{
	  struct thread *cur=thread_current ();
	  //set the e_status of the wait_state as the status
	  cur->wait_state->e_status = status;
	  //call thread_exit function which will then call process_exit()
	  // and syscall_exit() functions to update the status of the child 
	  //threads and also to close all the open files
	  thread_exit ();
	  NOT_REACHED ();
	}	

/* this function is called by thread_exit() function to make sure that
   all the files are closed before the thread exits.Also if any of them 
   is open then this function will close them. */
	void
	syscall_exit (void) 
	{
	  struct list_elem *next;
	  struct list_elem *ele;
	  struct thread *cur = thread_current (); 
	  for (ele = list_begin (&cur->file_descs);
		   ele != list_end (&cur->file_descs); 
		   ele = next)
		{
		  struct file_descriptor *f_d;
		  //get the next entry
		  f_d = list_entry (ele, struct file_descriptor, elem);
		  next = list_next (ele);
		  //acquire the file lock
		  lock_acquire (&file_lock);
		  //close the file
		  file_close (f_d->file);
		  //release the file lock
		  lock_release (&file_lock);
		  // free the f_d
		  free (f_d);
		}
	}
	
/* Exec system call. */
//----------------------------------------------------------------------

pid_t exec (const char *cmd_line) 
{
  char *ker_f = take_in_km (cmd_line);
  tid_t tid;
  //acquire the lock
  lock_acquire (&file_lock);
  //call process execute
  tid = process_execute (ker_f);
  //once we get the tid release the lock
  lock_release (&file_lock);
  //free the page
  palloc_free_page (ker_f);
 //return the tid
  return tid;
}
 
 /* Wait system call */
//----------------------------------------------------------------------
	int wait (pid_t child) 
	{
		// this function will call process_wait function which is in 
		// process.c that returns its exit status.
		return process_wait (child);
	}

/* Create system call */
//----------------------------------------------------------------------
	bool
	create (const char *file, unsigned initial_size) 
	{
	  bool f_res;
	  char *ker_f = take_in_km (file);
	  //acquire the file lock file_lock
	  lock_acquire (&file_lock);
	  //call the filesys_create function
	  f_res = filesys_create (ker_f, initial_size);
	  //release the lock once the status has been received
	  lock_release (&file_lock);
	  //free the page
	  palloc_free_page (ker_f);
	  //return the status received by the filesys_create
	  return f_res;
	}	
	
/* Remove system call */
//----------------------------------------------------------------------
	bool
	remove (const char *file) 
	{
	  bool f_res;
	  char *ker_f = take_in_km (file);
	  //acquire the file lock file_lock
	  lock_acquire (&file_lock);
	  //call the filesys_remove function
	  f_res = filesys_remove (ker_f);
	  //release the lock once the status has been received
	  lock_release (&file_lock);
	  //free the page
	  palloc_free_page (ker_f);
	  //return the status received by the filesys_create
	  return f_res;
	}
	
/* Open system call. */
//----------------------------------------------------------------------
	int open (const char *file) 
	{

	  char *ker_f = take_in_km (file);
	  struct file_descriptor *f_d;
	  int fd = -1;
	  f_d = malloc (sizeof *f_d);
	  //check if file descriptor f_d is not null
	  if (f_d != NULL)
		{
		  //acquire the file lock file_lock
		  lock_acquire (&file_lock);
		  //call the filesys_open function and get the file
		  f_d->file = filesys_open (ker_f);
		  //check if the file is not null
		  if(f_d->file == NULL)
		  {
			//if the file is null then free the space
			free (f_d);
		  }
		  else
			{
			  struct thread *cur = thread_current ();
			  //set the fd
			  fd = f_d->id = cur->next_value++;
			  //update the list of file descriptors inside the thread
			  //structure and the elem inside the file struct
			  list_push_front (&cur->file_descs, &f_d->elem);
			}
			//release the lock
		  lock_release (&file_lock);
		}
	  //free the page
	  palloc_free_page (ker_f);
	  //return the fd
	  return fd;
	}
 	
/* Filesize system call */
//----------------------------------------------------------------------
	int filesize (int fd) 
	{
	  int size;
	  struct file_descriptor *f_d = get_file_desc (fd);
	  //acquire the file lock file_lock
	  lock_acquire (&file_lock);
	  //call the file_length function to get the size
	  size = file_length (f_d->file);
	  //release the file lock
	  lock_release (&file_lock);
	  // return the size
	  return size;
	}	
	
/* Read system call */
//----------------------------------------------------------------------
int read (int fd, void *buffer_, unsigned size) 
{
  struct file_descriptor *f_d;
  uint8_t *read_buffer = buffer_;
  int total_bytes_read = 0;
  
  // fd keyboard reads by reading input_getc () and returns the 
  //number of bytes read
  if (fd == 0) 
    {
	  total_bytes_read = 0;
	  while((size_t) total_bytes_read < size)
	  {
        if (read_buffer >= (uint8_t *) PHYS_BASE || 
		!put_user (read_buffer++, input_getc ()))
		{
          thread_exit ();
		} 
		total_bytes_read++ ; 
	  }//end of while loop
      return total_bytes_read;
    }//end of if
	
  // fd all other reads.
  f_d = get_file_desc (fd);
  //acquire the file lock to start reading
  lock_acquire (&file_lock);
  while (size > 0) 
    {
	  off_t retval;
      // check the space left on the current page
      size_t rem_page_size;
	  rem_page_size= PGSIZE - pg_ofs(read_buffer);
	  //check the amount to be read and then start reading accordingly.
      size_t read_amt ;
      if(size<rem_page_size)
	  {
		read_amt=size;
	  }
	  else
	  {
		read_amt=rem_page_size;
	  }

      // Check if the read_buffer is valid
      if (!validate (read_buffer)) 
        {
		//release the lock since user is not valid and call thread_exit()
          lock_release (&file_lock);
          thread_exit ();
        }

      // start reading from file to a page 
      retval = file_read (f_d->file, read_buffer, read_amt);
      if (retval < 0)
        {
		  //set the total_bytes_read to -1 if it is 0
          if (total_bytes_read == 0)
		  {
            total_bytes_read = -1; 
		  }	
          break;
        }
		//increment the total_bytes_read to retval
      total_bytes_read= total_bytes_read  + retval;

      // If all the bytes have been read then break
      if (retval != (off_t) read_amt)
	  {
        break;
	  }
      // update the size and read_buffer values according to the retval
	  size =size- retval;
      read_buffer =read_buffer + retval;
      
    }
  //release the file lock once it has been read
  lock_release (&file_lock);
  //return the total total_bytes_read 
  return total_bytes_read;
}	

/* Write system call. */
//----------------------------------------------------------------------

int write (int fd, void  *buffer_, unsigned size) 
{

  uint8_t *write_buffer = buffer_;
  struct file_descriptor *f_d = NULL;
  int total_bytes_written = 0;

	// Lookup up file descriptor.
	if (fd != 1)
		f_d = get_file_desc (fd);
	//acquire the file lock to start reading
	lock_acquire (&file_lock);
	//loop till all the bytes have been written
	while (size > 0) 
    {
	  off_t retval;
      // check how much space is left on the current page 
      size_t rem_page_size;
	  rem_page_size = PGSIZE - pg_ofs(write_buffer);
	  //check the amount to be written and then start reading accordingly.
      size_t write_amt;// = size < rem_page_size ? size : rem_page_size;
	  if(size<rem_page_size)
	  {
		write_amt=size;
	  }
	  else
	  {
		write_amt=rem_page_size;
	  }
      // Check if the write_buffer is valid
      if (!validate (write_buffer)) 
        {
		//release the lock since user is not valid and call thread_exit()
         lock_release (&file_lock);
		 //then call thread_exit
         thread_exit ();
        }

      // perform write operation by call putbuf() function
      if (fd == 1)
        {
          putbuf (write_buffer, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (f_d->file, write_buffer, write_amt);
      if (retval < 0) 
        {
		  //set the total_bytes_read to -1 if it is 0
          if (total_bytes_written == 0)
		  {
            total_bytes_written = -1;
		  }
          break;
        }
	  //increment the total_bytes_written to retval	
      total_bytes_written =total_bytes_written + retval;

      // If all the bytes have been written then break
	  off_t check_write_amt=(off_t)write_amt;
      if (retval != check_write_amt)
	  {
        break;
	  }	
      // update the size and write_buffer values according to the retval
      write_buffer = write_buffer + retval;
      size = size - retval;
    }

	//release the file lock once it has been read
	lock_release (&file_lock);
 
  return total_bytes_written; 
}

/* Seek system call. */
//----------------------------------------------------------------------

void seek (int fd, unsigned position) 
	{
	  int success=0;
	  //initialize the file descriptor
	  struct file_descriptor *f_d = get_file_desc (fd);
	  //acquire the file lock
	  lock_acquire (&file_lock);
	  //check the offset position and if it is greater than 0 then call 
	  //file_seek() function
	  if ((off_t) position >= 0)
		file_seek (f_d->file, position);
	  //release the file lock once the seek operation is complete
	  lock_release (&file_lock);
	  //return success
	  return success;
	}

/* Tell system call */
//----------------------------------------------------------------------
int tell (int fd) 
{
  unsigned pos;
  //initialize the file descriptor with the fd input
  struct file_descriptor *f_d = get_file_desc (fd);
  //acquire the file lock
  lock_acquire (&file_lock);
  //get the pos by calling file_tell function
  pos = file_tell (f_d->file);
  //release the file lock once the pos is received
  lock_release (&file_lock);
  //return the pos
  return pos;
}

/* Close system call*/
//----------------------------------------------------------------------
void close (int fd) 
{
  int success=0;
  //initialize the file descriptor with the fd input
  struct file_descriptor *f_d = get_file_desc (fd);
  //acquire the file lock
  lock_acquire (&file_lock);
  //call the file_close function and close the file
  file_close (f_d->file);
  //release the file lock once the file has been close
  lock_release (&file_lock);
  //remove the file from the elem list in the file descriptor
  list_remove (&f_d->elem);
  //free the f_d
  free (f_d);
  //return success
  return success;
}