#!/usr/bin/env python
import os
import sys
import libseccomp.seccomp

syscalls = [
##############
# filesystem #
##############
  'open', 'openat', 'creat', # open and possibly create a file
  'open_by_handle_at', # obtain handle for a pathname and open file via a handle
  'close', # close a file descriptor
  'access', 'faccessat', # determine accessibility of a file relative to directory file descriptor
  'statx', # get file status (extended)
  '!oldstat', '!oldfstat', '!oldlstat', # get file status
  'stat', 'stat64', 'fstat', 'fstat64', 'fstatat64', 'newfstatat', 'lstat', 'lstat64', # get file status
  'statfs', 'statfs64', 'fstatfs', 'fstatfs64', # get filesystem statistics
  'ustat', # get filesystem statistics
  'flock', # apply or remove an advisory lock on an open file
  '!chmod', '!fchmod', '!fchmodat', # change permissions of a file
  '!chown', '!chown32', '!fchown', '!fchown32', '!fchownat', '!lchown', '!lchown32', # change ownership of a file
  'fcntl', # file control
  'fsync', # synchronize changes to a file
  'readlink', 'readlinkat', # read value of a symbolic link
  'rename', 'renameat', 'renameat2', # change the name or location of a file
  'unlink', 'unlinkat', # delete a name and possibly the file it refers to
  'symlink', 'symlinkat', # make a symbolic link relative to directory file descriptor
  'dup', 'dup2', # duplicate an open file descriptor
  '!quotactl', # manipulate disk quotas
  'umask', # set file mode creation mask
  '!mount', '!umount', '!umount2', # mount and umount filesystem
  'memfd_create', # create an anonymous file
#################
# file contents #
#################
  'read', # read from a file descriptor
  'write', # write to a file descriptor
  'pread64', # read from to a file descriptor at a given offset
  'pwrite64', # write to a file descriptor at a given offset
  'readv', 'preadv', 'preadv2', # read data from multiple buffers
  'writev', 'pwritev', 'pwritev2', # write data into multiple buffers
  'lseek', #  move the read/write file offset
  '!_llseek', # reposition read/write file offset for lage files on 32-bit platforms
  'fallocate', # preallocate or deallocate space to a file
  'fadvise64', 'fadvise64_64', # predeclare an access pattern for file data
  'readahead', # initiate file readahead into page cache
  'ftruncate', 'ftruncate64', # truncate a file to a specified length
###########
# devices #
###########
  'ioctl', # control device
  'ioperm', # set port input/output permissions
  'iopl', # change I/O privilege level
  'ioprio_set', 'ioprio_get', # set/get I/O scheduling class and priority
  'io_cancel', # cancel an outstanding asynchronous I/O operation 
  'io_destroy', # destroy an asynchronous I/O context
  'io_getevents', # read asynchronous I/O events from the completion queue
  'io_setup', # create an asynchronous I/O context
  'io_submit', # submit asynchronous I/O blocks for processing
  'mknod', 'mknodat', # create a special or ordinary file
###############
# directories #
###############
  'getdents', 'getdents64', # get directory entries
  'mkdir', 'mkdirat', # create a directory
  'rmdir', # delete a directory
  'getcwd', # get current working directory
  'chdir', 'fchdir', # change working directory
###########
# sockets #
###########
  'socket', # create an endpoint for communication
  'socketpair', # create a pair of connected sockets
  'bind', # bind a name to a socket
  'connect', # set and get signal alternate stack context
  'accept', 'accept4', # accept a connection on a socket
  'sendto', # send a message on a socket
  'sendmsg', # send a message on a socket using a message structure
  'sendmmsg', # send multiple message on a socket
  'recvmsg', # receive a message from a socket
  'recvfrom', # receive a message from a socket
  '!socketcall', # socket system calls
  'setsockopt', 'getsockopt', # set/get the socket options
  'getsockname', # get the socket name
  'getpeername', # get the name of the peer socket
  'shutdown', # shut down part of a full-duplex connection
#############
# processes #
#############
  'getpid', # get process identification
  'setsid', # creates a session and sets the process group ID
  'setpgid', 'getpgid', # set/get the process group ID for a process
  'getpgrp', # get the process group ID
  'gettid', # get thread identification
  'capset', 'capget', # set/get capabilities of thread(s)
  '!set_tid_address', # set pointer to thread ID
  'prctl', # operations on a process
  'arch_prctl', # set architecture-specific thread state
  '!fork', # create a child process (replaced by clone with SIGCHLD)
  'clone', # create a child process
  'execve', # execute a program
  'execveat', # execute program relative to a directory file descriptor
  'kill', # send signal to a process
  'tkill', 'tgkill', # send a signal to a thread
  'exit', # terminate the calling process
  'exit_group', # exit all threads in a process
  'pipe', 'pipe2', # create an interprocess channel
  'getppid', # get parent process identification
###################
# synchronisation #
###################
  'select', 'pselect6', '_newselect', # wait until one or more file descriptors become "ready"
  'futex', # fast user-space locking
  'set_robust_list', 'get_robust_list', # set/get list of robust futexes
  'poll', 'ppoll', # wait for some event on a file descriptor
  '!oldwait4', # wait for process to change state, BSD style
  'wait4', # wait for process to change state, BSD style
  'epoll_create', 'epoll_create1', # open an epoll file descriptor
  '!epoll_ctl_old', # control interface for an epoll file descriptor
  'epoll_ctl', # control interface for an epoll file descriptor
  'epoll_wait', 'epoll_pwait', # wait for an I/O event on an epoll file descriptor
  'eventfd', 'eventfd2', # create a file descriptor for event notification
  'pause', # wait for signal
##############
# scheduling #
##############
  'sched_yield', # yield the processor
  'sched_setaffinity', 'sched_getaffinity', # set and get a thread's CPU affinity mask
  'sched_get_priority_max', 'sched_get_priority_min', # get priority limits (REALTIME)
  'sched_setattr', 'sched_getattr', # set and get scheduling policy and attributes
  'sched_setparam', 'sched_getparam', # set and get scheduling parameters (REALTIME)
  'sched_setscheduler', 'sched_getscheduler', # get scheduling policy (REALTIME)
  'sched_rr_get_interval', # get execution time limits (REALTIME)
  'setpriority', 'getpriority', # get and set the nice value
###########
# signals #
###########
  'sigaction', 'rt_sigaction', # examine and change a signal action
  'sigprocmask', 'rt_sigprocmask', # examine and change blocked signals
  'sigreturn', 'rt_sigreturn', # return from signal handler and cleanup stack frame
  'sigpending', 'rt_sigpending', # examine pending signals
  'sigsuspend', 'rt_sigsuspend', # wait for a signal
  'rt_sigqueueinfo', 'rt_tgsigqueueinfo', # queue a signal and data
  'rt_sigtimedwait', # synchronously wait for queued signals
  'sigaltstack', # set and get signal alternate stack context
  'alarm', # set an alarm clock for delivery of a signal
##########
# memory #
##########
  '!brk', # change data segment size
  'madvise', # give advice about use of memory
  'mmap', 'mmap2', 'munmap', # map files or devices into memory
  'mprotect', # set protection of memory mapping
  'set_mempolicy', # set default NUMA memory policy for a thread and its children
  'get_mempolicy', # retrieve NUMA memory policy for a thread
  'set_thread_area', 'get_thread_area', # set a GDT entry for thread-local storage
  'shmctl', # XSI shared memory control operations
  'shmat', # XSI shared memory attach operation
  'shmdt', # XSI shared memory detach operation
  'shmget', # get an XSI shared memory segment
########
# user #
########
  'setuid', 'setuid32', # set user identity
  'getuid', 'getuid32', # get real user ID
  'setgid', 'setgid32', # set group identity
  'getgid', 'getgid32', # get real group ID 
  'setreuid', 'setreuid32', # set real and/or effective user ID
  'geteuid', 'geteuid32', # get effective user ID 
  'setregid', 'setregid32', # set real and/or effective group ID
  'getegid', 'getegid32', # get effective group ID
  'setresuid', 'setresuid32', # set real, effective and saved group IDs
  'getresuid', 'getresuid32', # get real, effective and saved group IDs
  'setresgid', 'setresgid32', # set real, effective and saved group IDs
  'getresgid', 'getresgid32', # get real, effective and saved group IDs
  'setfsuid', 'setfsuid32', # set user identity used for filesystem checks
  'setfsgid', 'setfsgid32', # set group identity used for filesystem checks
########
# time #
########
  '!settimeofday', 'gettimeofday', # set/get time of day
  '!clock_settime', # set the time of the specified clock
  '!clock_gettime', # set the time of the specified clock
  'clock_getres', # finds the resolution (precision) of the specified clock
  'clock_nanosleep', # high resolution sleep
  '!clock_adjtime', # correct the time to synchronize the system clock
##########
# system #
##########
  '!sethostname', # set hostname
  '!_sysctl', # read/write system parameters
  '!olduname', '!oldolduname', # get name and information about current kerne
  'uname', # get name and information about current kernel
  'seccomp', # operate on Secure Computing state of the process
  'sysinfo', # return system information
  'getrusage', # get information about resource utilization
  'setrlimit', 'getrlimit', 'ugetrlimit', 'prlimit64', # set/get resource limits
  '!reboot', # reboot or enable/disable Ctrl-Alt-Del
##########
# others #
##########
  'getrandom', # obtain a series of random bytes
  'ipc', # System V IPC system calls
  '!restart_syscall', # restart a system call after interruption by a stop signal
]

unimplemented = [ 'afs_syscall', 'break', 'ftime', 'getpmsg', 'gtty', 'lock', 'mpx', 'prof', 'profil', 'putpmsg', 'security', 'stty', 'tuxcall', 'ulimit', 'vserver' ]

specials = {
   # needed by strace -qcf ?
  #'restart_syscall': libseccomp.seccomp.LOG,
}

blacklist = []
whitelist = []
for syscall in syscalls:
  if syscall.startswith('!'):
    blacklist.append(syscall[1:])
  else:
    whitelist.append(syscall)

f = libseccomp.seccomp.SyscallFilter(defaction=libseccomp.seccomp.LOG)
for syscall in blacklist:
  try:
    f.add_rule( libseccomp.seccomp.ERRNO(126), syscall )
  except RuntimeError as e:
    print('Blacklist error on syscall "{}"'.format(syscall))
    print(e)
for syscall in whitelist:
  try:
    f.add_rule( libseccomp.seccomp.ALLOW, syscall )
  except RuntimeError as e:
    print('Whitelist error on syscall "{}"'.format(syscall))
    print(e)
for syscall in unimplemented:
  try:
    f.add_rule( libseccomp.seccomp.KILL, syscall )
  except RuntimeError as e:
    print('Unimplemented list error on syscall "{}"'.format(syscall))
    print(e)
for syscall, action in specials.items():
  try:
    f.add_rule( action, syscall )
  except RuntimeError as e:
    print('Specials list error on syscall "{}"'.format(syscall))
    print(e)

# load the filter into the kernel
f.load()

# start shell
print('Blacklisted:{} Unimplemented:{} Whitelisted:{}'.format(len(blacklist),len(unimplemented),len(whitelist)))
print("ENTER")
os.system('zsh')
print("EXIT")
