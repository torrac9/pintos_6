#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
// #include "include/lib/user/syscall.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void get_argument(void *rsp, int **arg, int count);
void check_address(void *addr);
int add_file_to_fdt(struct file *file);
void remove_file_from_fdt(int fd);
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
tid_t fork (const char *thread_name, struct intr_frame *f);
int exec (char *file);
int wait (int);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct lock filesys_lock;
void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	/* system call이 rax에 저장한 syscall number에 따라 각기 다른 작업 수행 */
	switch(f->R.rax){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);	// 인자가 있으므로 interrupt frame에서 해당 인자를 찾는다.
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);	// 리턴값도 있으므로 해당 리턴값을 rax에 저장
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
	}
}

void check_address(void *addr){
	if(addr == NULL || !is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

static struct file *find_file_by_fd(int fd){
	if(fd < 0 || fd >= FDCOUNT_LIMIT){
		return NULL;
	}
	return thread_current()->fdTable[fd];
}

int add_file_to_fdt(struct file *file){
	struct thread *cur = thread_current();
	struct file **fdt = thread_current()->fdTable;

	// fd위치가 범위 안에 있고, fd table의 인덱스 위치와 일치
	while(cur->fdIdx < FDCOUNT_LIMIT && fdt[cur->fdIdx]){
		cur->fdIdx++;
	}

	if(cur->fdIdx >= FDCOUNT_LIMIT){	// fd table full
		return -1;
	}

	fdt[cur->fdIdx] = file;
	return cur->fdIdx;
}

void remove_file_from_fdt(int fd){
	if(fd < 0 || fd >= FDCOUNT_LIMIT){	// invalid fd
		return;
	}

	thread_current()->fdTable[fd] = NULL;
}

/* system call 인자를 kernel에 복사 */
/* stack에 저장되어 있는 argv들을 차례대로 읽어서 arg배열에 저장 */
void get_argument(void *rsp, int **arg, int count){
	rsp = (int64_t *)rsp + 2;	// 원래 stack pointer에서 2칸(16byte) 올라감
	for(int i = 0; i < count; i++){
		arg[i] = rsp;
		rsp = (int64_t *)rsp + 1;
	}
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

int exec(char *file){
	check_address(file);

	// process.c 파일의 process_create_initd 함수와 유사하다.
	// 단, 스레드를 새로 생성하는 건 fork에서 수행하므로
	// 이 함수에서는 새 스레드를 생성하지 않고 process_exec을 호출한다.

	// process_exec 함수 안에서 filename을 변경해야 하므로
	// 커널 메모리 공간에 cmd_line의 복사본을 만든다.
	// (현재는 const char* 형식이기 때문에 수정할 수 없다.)
	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		exit(-1);							  // 메모리 할당 실패 시 status -1로 종료한다.
	strlcpy(cmd_line_copy, file, PGSIZE); // cmd_line을 복사한다.

	// 스레드의 이름을 변경하지 않고 바로 실행한다.
	if (process_exec(cmd_line_copy) == -1)
		exit(-1); // 실패 시 status -1로 종료한다.
}

int wait(int pid){
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file){
	check_address(file);
	struct file *open_file = filesys_open(file);

	if(open_file == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	// fd table에 file 추가
	int fd = add_file_to_fdt(open_file);

	// if fd table full
	if(fd == -1)
		file_close(open_file);
	lock_release(&filesys_lock);
	return fd;
}

int filesize(int fd){
	struct file *open_file = find_file_by_fd(fd);
	if(open_file == NULL)
		return -1;
	
	return file_length(open_file);
}

int read(int fd, void *buffer, unsigned size){
	check_address(buffer);

	char *ptr = (char *)buffer;
	int bytes_read = 0;

	lock_acquire(&filesys_lock);
	if (fd == 0){
		for (int i = 0; i < size; i++){
			*ptr++ = input_getc();
			bytes_read++;
		}
		lock_release(&filesys_lock);
	}
	else{
		if (fd < 2){
			lock_release(&filesys_lock);
			return -1;
		}
		struct file *file = find_file_by_fd(fd);
		if (file == NULL){
			lock_release(&filesys_lock);
			return -1;
		}
		bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	}
	//printf("1341351345134read: %d\n", bytes_read);
	return bytes_read;
}

int write(int fd, const void *buffer, unsigned size){
	check_address(buffer);
	int bytes_write = 0;
	if (fd == 1)
	{
		putbuf(buffer, size);
		bytes_write = size;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *file = find_file_by_fd(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	}
	//printf("51451345134write: %d\n", bytes_write);
	return bytes_write;
}

void seek(int fd, unsigned position){
	struct file *seek_file = find_file_by_fd(fd);

	if(seek_file == NULL)
		return;
	
	file_seek(seek_file, position);
}

unsigned tell(int fd){
	struct file *tell_file = find_file_by_fd(fd);
	if(tell_file <= 2)
		return;
	
	return file_tell(tell_file);
}

void close(int fd){
	struct file *fileobj = find_file_by_fd(fd);

	if(thread_current()->fdTable[fd] != NULL)
		file_close(thread_current()->fdTable[fd]);

	if(fileobj == NULL)
		return;
	
	remove_file_from_fdt(fd);
}