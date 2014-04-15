#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void syscall_exit (void);

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

#endif /* userprog/syscall.h */
