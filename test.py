#!/usr/bin/env python
import os
import sys
import libseccomp.seccomp
# create a filter object with a default KILL action
#f = libseccomp.seccomp.SyscallFilter(defaction=libseccomp.seccomp.KILL)
blacklist = [
  '_sysctl', # read/write system parameters
  'fchown', # change owner and group of a file
  'fchownat', # change owner and group of a file relative to directory file descriptor
# exotic syscals
  '_llseek', # reposition read/write file offset for lage files on 32-bit platforms
# deprecated syscalls
  'fork', # create a child process (replaced by clone with SIGCHLD)
  'oldwait4', # wait for process to change state, BSD style
  'epoll_ctl_old', # control interface for an epoll file descriptor
  'oldstat', 'oldfstat', 'oldlstat', # get file status
  'oldwait4', # wait for process to change state, BSD style
  'olduname', 'oldolduname', # get name and information about current kernel
]
whitelist = [
# files
  'read', # read from a file descriptor
  'write', # write to a file descriptor
  'pread64', # read from to a file descriptor at a given offset
  'pwrite64', # write to a file descriptor at a given offset
  'readv', 'preadv', 'preadv2' # read data from multiple buffers
  'writev', 'pwritev', 'pwritev2' # write data into multiple buffers
  'lseek', #  move the read/write file offset
# directories
  'getdents', 'getdents64', # get directory entries
# filesystem
  'access', 'faccessat', # determine accessibility of a file relative to directory file descriptor
  'statx', # get file status (extended)
  'stat', 'stat64', 'fstat', 'fstat64', 'fstatat64', 'newfstatat', # get file status
  'statfs' 'statfs64', 'fstatfs', 'fstatfs64', # get filesystem statistics
  'flock', # apply or remove an advisory lock on an open file
  'fcntl', # file control
  'fsync', # synchronize changes to a file
# sockets
  'accept', 'accept4', # accept a connection on a socket
  'recvmsg', # receive a message from a socket
# processes
  'clone', # create a child process
# waiting/synchronisation
  'futex', # fast user-space locking
  'sched_yield', # yield the processor
  'poll', # input/output multiplexing
  'epoll_create', 'epoll_create1', # open an epoll file descriptor
  'epoll_ctl', # control interface for an epoll file descriptor
  'epoll_wait', 'epoll_pwait', # wait for an I/O event on an epoll file descriptor
  'wait4', # wait for process to change state, BSD style
# signals
  'sigaction', 'rt_sigaction', # examine and change a signal action
  'sigprocmask', 'rt_sigprocmask', # examine and change blocked signals
  'sigreturn', 'rt_sigreturn', # return from signal handler and cleanup stack frame
  'sigpending', 'rt_sigpending', # examine pending signals
  'sigsuspend', 'rt_sigsuspend', # wait for a signal
  'rt_sigqueueinfo', 'rt_tgsigqueueinfo', # queue a signal and data
  'rt_sigtimedwait', # synchronously wait for queued signals
# memory
  'mprotect', # set protection of memory mapping
# others
  'uname', # get name and information about current kernel
]
specials = {
  # needed by strace -qcf ?
  'restart_syscall': defaction=libseccomp.seccomp.LOG,
}

f = libseccomp.seccomp.SyscallFilter(defaction=libseccomp.seccomp.LOG)
for syscall in blacklist:
  f.add_rule( libseccomp.seccomp.ERRNO(126), syscall )
for syscall in whitelist:
  f.add_rule( libseccomp.seccomp.ALLOW, syscall )
for syscall, action in specials.items():
  f.add_rule( action, syscall )

#whitelist = ['open','close','read','write','rt_sigreturn','exit']
# add syscall filter rules to allow certain syscalls
#f.add_rule(libseccomp.seccomp.ALLOW, "open")
#f.add_rule(libseccomp.seccomp.ALLOW, "close")
#f.add_rule(libseccomp.seccomp.ALLOW, "read", libseccomp.seccomp.Arg(0, libseccomp.seccomp.EQ, sys.stdin.fileno()))
#f.add_rule(libseccomp.seccomp.ALLOW, "write", libseccomp.seccomp.Arg(0, libseccomp.seccomp.EQ, sys.stdout.fileno()))
#f.add_rule(libseccomp.seccomp.ALLOW, "write", libseccomp.seccomp.Arg(0, libseccomp.seccomp.EQ, sys.stderr.fileno()))
#f.add_rule(libseccomp.seccomp.ALLOW, "rt_sigreturn")
#f.add_rule(libseccomp.seccomp.ALLOW, "exit_group")
#f.add_rule(libseccomp.seccomp.ALLOW, "exit")
#f.add_rule(libseccomp.seccomp.ALLOW, "fork")
#f.add_rule(libseccomp.seccomp.ALLOW, "shmctl")
# load the filter into the kernel
f.load()
#print("hallo")
os.system('zsh')
