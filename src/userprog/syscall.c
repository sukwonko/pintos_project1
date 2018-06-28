#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h" /* Added to use 'shutdown_power_off' function */
#include "filesys/filesys.h" /* Added to use filesystem related function */
#include "filesys/file.h" /* Added to use filesystem related function */
#include "devices/input.h" /* Added to use input_getc() function */
#include "userprog/process.h" /* Added to use process_execute() */
#include "threads/synch.h" /* Added to use lock */
#include "filesys/inode.h"
#include "filesys/directory.h"

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock; /* Added to use filesystem lock to prevent unexpected situation. */

void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

void halt(void);
void exit(int status);
bool create(const char *file, unsigned int initial_size);
bool remove(const char *file);
tid_t exec(char *exec_filename);
int wait(tid_t tid);
int open(const char *open_filename);
int filesize(int fd);
int read(int fd, char *buffer, unsigned int size);
int write(int fd, char *buffer, unsigned int size);
void seek(int fd, unsigned int position);
unsigned int tell(int fd);
void close(int fd);

void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
	int status, fd, pid;
	char *file=NULL, *filename=NULL;
	void *buffer;
	unsigned int size,position;
	int *argument[4]={0, }; //Arguments for system call will be stored temporary.

	check_address(f->esp);

	switch(*(int *)(f->esp))
	{
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			get_argument(f->esp,(int *)argument, 1); //One argument will be used.
			check_address((void *)(argument[0]));
			status =*(int *)argument[0]; //Type casting.
			exit(status);
			break;

		case SYS_EXEC:
			get_argument(f->esp, (int *)argument, 1); //One argument will be used.
			check_address((void *)(argument[0]));	
			filename =*(char**)argument[0]; //Type casting.
			f->eax = exec(filename); //Store return value to eax.
			break;
			
		case SYS_WAIT:
			get_argument(f->esp,(int *)argument, 1); //One argument will be used.
			check_address((void *)(argument[0]));
			pid = *(int *)argument[0]; //Type casting.
			f->eax = wait(pid); //Store return value to eax.
			break;

		case SYS_CREATE:
			get_argument(f->esp, (int *)argument, 2); //Two arguments will be used.
			check_address((void *)(argument[0]));
			check_address((void *)(argument[1]));
			file = *(char **)argument[0];
			size = *(int *)argument[1];
			f->eax = create(file, size); //Store return value to eax.
			break;
			
		case SYS_REMOVE:
			get_argument(f->esp, (int *)argument, 1); //One argument will be used.
			check_address((void *)(argument[0]));
			file =*(char**)argument[0]; //Type casting.
			f->eax = remove(file); //Store return value to eax.
			break;

		case SYS_OPEN:
			get_argument(f->esp,(int *) argument, 1); //One argument will be used.
			check_address((void *)(argument[0]));
			file =*(char**)argument[0];
			f->eax = open(file); //Store return value to eax.
			break;
			
		case SYS_FILESIZE:
			get_argument(f->esp, (int *)argument, 1); //One argument will be used.
			check_address((void *)(argument[0]));
			fd =*(int *)argument[0];
			f->eax = filesize(fd); //Store return value to eax.
			break;

		case SYS_READ:
			get_argument(f->esp, (int *)argument, 3); //Three arguments will be used.
			check_address((void *)(argument[0]));
			check_address((void *)(argument[1]));
			check_address((void *)(argument[2]));
			fd =*(int *)argument[0];
			buffer = *(void **)argument[1];
			size = *(int *)argument[2];
		 	check_address(buffer+size);	
			f->eax = read(fd, buffer, size); //Store return value to eax.
			break;

		case SYS_WRITE:
			get_argument(f->esp, (int *)argument, 3); //Three arguments will be used.
			check_address((void *)(argument[0]));
			check_address((void *)(argument[1]));
			check_address((void *)(argument[2]));
			fd =*(int *)argument[0];
			buffer = *(void **)argument[1];
			size = *(int *)argument[2];
		 	check_address(buffer+size);	
			f->eax = write(fd, buffer, size); //Store return value to eax.
			break;

		case SYS_SEEK:
			get_argument(f->esp,(int *) argument, 2); //Two arguments will be used.
			check_address((void *)(argument[0]));
			check_address((void *)(argument[1]));
			fd = *(int *)argument[0];
			position = *(unsigned int *)(argument[1]);
			seek(fd, position); //Store return value to eax.
			break;

		case SYS_TELL:
			get_argument(f->esp,(int *) argument, 1); //one arguments will be used.
			check_address((void *)(argument[0]));
			fd = *(int *)argument[0];
			f->eax = tell(fd); //Store return value to eax.
			break;
			
		case SYS_CLOSE:
			get_argument(f->esp, (int *)argument, 1); //one arguments will be used.
			check_address((void *)(argument[0]));
			fd = *(int *)argument[0];
			close(fd); //Store return value to eax.
			break;

		default:
			thread_exit();	
	}
}

/* Check address if it is valid address */
void
check_address(void *addr)
{
	/* Check address and if address value is out of range, exit process. */
	if(addr <(void*)0x08048000 || addr >=(void*)0xc0000000) exit(-1);
}

/* Get argument from esp and store them into kernel stack */
void
get_argument(void *esp, int *arg, int count)
{
	int i;
	for(i = 0; i < count; i++)
	{
		esp = esp + 4;
		check_address(esp);
		arg[i] =*(int *)esp; /* Insert each esp address into kernel stack */
	}
}

/* Shutdown system */
void
halt(void)
{
	shutdown_power_off();
}

/* Exit current process */
void
exit(int status)
{
	struct thread *current_thread = thread_current();
	printf("%s: exit(%d)\n", current_thread->name, status); //Display exit task information.
	current_thread->exit_status = status; //Store exit status into child_process descriptor.
	
	thread_exit();
}

/* Create file */
bool
create(const char *file, unsigned int initial_size)
{
	if(file ==NULL) return false;

	lock_acquire(&filesys_lock); //lock for atomic file operation.
	bool result = filesys_create(file, initial_size);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return result; //If success, return true. Else, return false.
}

/* Remove file */
bool
remove(const char *file)
{
	if(file ==NULL) return false;

	lock_acquire(&filesys_lock); //lock for atomic file operation.
	bool result = filesys_remove(file);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return result; //If success, return true. Else, return false.return result;
}

/* Execute child process */
tid_t
exec(char *exec_filename)
{
	tid_t executed_process_tid = process_execute(exec_filename); //Get tid of executed process.
 	if(executed_process_tid == TID_ERROR) return TID_ERROR;
	struct thread *child = get_child_process(executed_process_tid); //Get object of correspond tid.

	sema_down(&child->load_sema);

	if(child->is_load) return executed_process_tid;
	else return TID_ERROR;
}

/* Wait for child process to exit */
int
wait(tid_t tid)
{
	return process_wait(tid);
}

/* Open file */
int
open(const char *open_filename)
{

	struct file *open_file = filesys_open(open_filename); //Get file object
	if(!open_file || !open_filename)
	{
		return -1;
	}

	int open_file_fd = process_add_file(open_file);

	return open_file_fd;
}

/* Get filesize of correspond file descriptor */
int
filesize(int fd)
{
	struct file *target_file = process_get_file(fd); //Get file object
	if(!target_file)
	{
		return -1;
	}

	int file_size = file_length(target_file);

	return file_size;
}

/* Get data from input buffer. */
int
read(int fd, char *buffer, unsigned int size)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.

	if(fd == 0) //STDIN
	{
		unsigned int i;
		char tmp;
		for(i = 0; i < size; i++)
		{
			tmp = input_getc();
			if(tmp == '\n') break;
			else{
				buffer[i] = tmp;
			}
		}
		lock_release(&filesys_lock); //Unlock for atomic file operation.

		return i;
	}

	
	struct file *read_file = process_get_file(fd); //Get file object
	if(!read_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	int read_size = file_read(read_file, buffer, size);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return read_size;
}

/* Put data into output buffer. */
int
write(int fd, char *buffer, unsigned int size)
{

	lock_acquire(&filesys_lock); //lock for atomic file operation.
	
	if(fd == 1) //STDOUT
	{
		putbuf(buffer, size);
		lock_release(&filesys_lock); //Unlock for atomic file operation.

		return size;
	}

	struct file *write_file = process_get_file(fd); //Get file object
	if(!write_file || !buffer)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	int write_size = file_write(write_file, buffer, size);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return write_size;
}

/* Move offset of file */
void
seek(int fd, unsigned int position)
{

	struct file *seek_file = process_get_file(fd);
	if(!seek_file)
	{
		return;
	}

	file_seek(seek_file, (off_t)position);
}

/* Get current offset of file. */
unsigned int
tell(int fd)
{

	struct file *tell_file = process_get_file(fd); //Get file object
	if(!tell_file)
	{
		return -1;
	}

	off_t offset = file_tell(tell_file);

	return offset;
}

/* Close file */
void
close(int fd)
{
	process_close_file(fd);
}

