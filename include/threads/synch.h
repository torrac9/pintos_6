#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
	unsigned value;             /* Current value. */
	struct list waiters;        /* List of waiting threads. */
};

void sema_init (struct semaphore *, unsigned value);	// initialize semaphore to the given value
void sema_down (struct semaphore *);	// semaphore를 요청하고 획득했을 때 value를 1 낮춤
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);	// semaphore를 반환하고 value를 1 높임
void sema_self_test (void);

/* Lock. */
struct lock {
	struct thread *holder;      /* Thread holding lock (for debugging). */
	struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init (struct lock *);	// lock 자료구조 초기화
void lock_acquire (struct lock *);	// lock 요청
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);	// lock 반환
bool lock_held_by_current_thread (const struct lock *);

/* Condition variable. */
struct condition {
	struct list waiters;        /* List of waiting threads. */
};

void cond_init (struct condition *);	// condition variable 자료구조 초기화
void cond_wait (struct condition *, struct lock *);	// condition variable을 통해 signal 기다림
void cond_signal (struct condition *, struct lock *);	// condition variable에서 기다리는 가장 높은 우선순위 thread에 signal 보냄
void cond_broadcast (struct condition *, struct lock *);	// condition variable에서 기다리는 모든 thread에 signal 보냄

/* Optimization barrier.
 *
 * The compiler will not reorder operations across an
 * optimization barrier.  See "Optimization Barriers" in the
 * reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

// 첫 번째 인자로 주어진 semaphore를 위해 대기 중인 가장 높은 우선순위의 thread와 두번 째 인자로 주어진 semaphroe를 위해 대기 중인 가장 높은 우선순위의 thread와 비교
bool cmp_sem_priority (const struct list_elem *a, const struct list_elem *b, void *aux);

#endif /* threads/synch.h */
