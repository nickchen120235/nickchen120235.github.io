---
layout: post
title: Linux Kernel Scheduling
tags: [Linux]
---

## Objective
Create an entry `ctx` for each process. It is initialized with `0` and will increase by `1` whenever the process runs. One can see the value of it using `cat /proc/<pid>/ctx`.The target is to know how the scheduler works with this kind of interactive process.

## Modifying the source code
Here we’re using the latest longterm version of kernel (5.10.31), but the same logic should apply between different versions.

### `include/linux/sched.h`
Every process has a `struct task_struct` which defines everything about it, so the first step is to add `ctx` inside the structure.

So the first part of it looks like this
```c
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
  /*
   * For reasons of header soup (see current_thread_info()), this
   * must be the first element of task_struct.
   */
  struct thread_info    thread_info;
#endif
  /* -1 unrunnable, 0 runnable, >0 stopped: */
  volatile long     state;

  /*
   * This begins the randomizable portion of task_struct. Only
   * scheduling-critical items should be added above here.
   */
  randomized_struct_fields_start

  void        *stack;
  refcount_t      usage;
  /* Per task flags (PF_*), defined further below: */
  unsigned int      flags;
  unsigned int      ptrace;

  /* ... */
}
```
We should add our `int ctx` before `randomized_struct_fields_start` because, well, it cannot randomizied. After adding it should be something like
```c
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
  /*
   * For reasons of header soup (see current_thread_info()), this
   * must be the first element of task_struct.
   */
  struct thread_info    thread_info;
#endif
  /* -1 unrunnable, 0 runnable, >0 stopped: */
  volatile long     state;

  /* Added by Nick */
  int ctx; // ctx will be initialized as 0 and increases per call.

  /*
   * This begins the randomizable portion of task_struct. Only
   * scheduling-critical items should be added above here.
   */
  randomized_struct_fields_start

  void        *stack;
  refcount_t      usage;
  /* Per task flags (PF_*), defined further below: */
  unsigned int      flags;
  unsigned int      ptrace;

  /* ... */
}
```

### `kernel/fork.c`
This is where every process is created. `ctx` should be initialized here. You can search for `struct task_struct` and go through all hits, but there’s a hint (?) in the source code
```c
/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 *
 * args->exit_signal is expected to be checked for sanity by the caller.
 */
```
This is the `kernel_clone()` function, where the real magic happens. It defines something, checks something, then creates a copy of the target process by calling `copy_process()`, which
```c
/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
```
And if it successfully returns, a `struct task_struct*` of the process will be returned, meaning that process is created (but not yet running, according to its description). Then more checks and things happens. And finally, it is started by `wake_up_new_task()`.

So `ctx` should be initialized within this section, and where I choose to do it is right after the first check
```c
 /* ... */

  p = copy_process(NULL, trace, NUMA_NO_NODE, args);
  add_latent_entropy();

  if (IS_ERR(p))
    return PTR_ERR(p);

  /* Added by Nick */
  p->ctx = 0; // initialize ctx here

  /* ... */
```

### `kernel/sched/core.c`
So now it’s initialized whenever the process is created. The next step is to tell the kernel to increase it whenever it’s active. And this is done by scheduling.

Take a look at the first comment block about how it works, and you’ll find some interesting functions

- `prepare_task()`: claim the task as running
- `activate_task()`: enqueue the task
- `deactivate_task()`: dequeue the task
- `finish_task()`: the last reference to the task

`prepare_task()` and `finish_task()` are for SMP (Symmetric multiprocessing). What we really care is `activate_task()` and `deactivate_task()`, which if we want ctx to increase every time it’s active, we should put the increment inside `activate_task()`. So something like this would work
```c
void activate_task(struct rq *rq, struct task_struct *p, int flags)
{
  enqueue_task(rq, p, flags);

  p->on_rq = TASK_ON_RQ_QUEUED;

  /* Added by Nick */
  p->ctx = p->ctx + 1; // increases ctx by 1 everytime it is activated
}
```

### `fs/proc/base.c`
The final and probably the most difficult step is to create an entry under `/proc/<pid>`.

Now try this, open the terminal and `ls /proc/<whatever-pid>`
```sh
❯ ls /proc/11544
 arch_status         cwd        mem            patch_state   stat
 attr                environ    mountinfo      personality   statm
 autogroup           exe        mounts         projid_map    status
 auxv                fd         mountstats     root          syscall
 cgroup              fdinfo     net            sched         task
 clear_refs          gid_map    ns             schedstat     timens_offsets
 cmdline             io         numa_maps      sessionid     timers
 comm                limits     oom_adj        setgroups     timerslack_ns
 coredump_filter     loginuid   oom_score      smaps         uid_map
 cpu_resctrl_groups  map_files  oom_score_adj  smaps_rollup  wchan
 cpuset              maps       pagemap        stack
```
Give those entries a search, and you’ll end up in a array `tgid_base_stuff[]`, where all entries are created with its type, name, permission, file operations
```c
static const struct pid_entry tgid_base_stuff[] = {
  DIR("task",       S_IRUGO|S_IXUGO, proc_task_inode_operations, proc_task_operations),
  DIR("fd",         S_IRUSR|S_IXUSR, proc_fd_inode_operations, proc_fd_operations),
  DIR("map_files",  S_IRUSR|S_IXUSR, proc_map_files_inode_operations, proc_map_files_operations),
  DIR("fdinfo",     S_IRUSR|S_IXUSR, proc_fdinfo_inode_operations, proc_fdinfo_operations),
  DIR("ns",   S_IRUSR|S_IXUGO, proc_ns_dir_inode_operations, proc_ns_dir_operations),
#ifdef CONFIG_NET
  DIR("net",        S_IRUGO|S_IXUGO, proc_net_inode_operations, proc_net_operations),
#endif
  REG("environ",    S_IRUSR, proc_environ_operations),
  REG("auxv",       S_IRUSR, proc_auxv_operations),
  ONE("status",     S_IRUGO, proc_pid_status),
  ONE("personality", S_IRUSR, proc_pid_personality),
  ONE("limits",   S_IRUGO, proc_pid_limits),

  /* ... */
}
```
And after some research (?), try `cat /proc/<pid>/timerslack_ns`, and you’ll find the output is like what we want
```sh
# cat /proc/11544/timerslack_ns
50000
```
So we can create an entry like `REG("ctx", S_IRUSR, my_ctx_ops)`, but here’s the problem: we have yet tell the kernel how to read the value. The plan is to implement (or use predefined routines) `open`, `read`, `llseek`, `release` of `struct file_operations`.

Take a look at how the operations of `timerslack_ns` is defined
```c
static const struct file_operations proc_pid_set_timerslack_ns_operations = {
  .open   = timerslack_ns_open,
  .read   = seq_read,
  .write    = timerslack_ns_write,
  .llseek   = seq_lseek,
  .release  = single_release,
};
```
So we have to implement `open`, and can use predefined functions for `read` and `llseek`, `release`, great!

`timerslack_ns_open()` is a more like a wrapper function of `single_open()`, which is defined in `seq_file`, and , yeah, we still have to implement our own read function, as a parameter of `single_open()`.

But I mean, take a look at `timerslack_ns_show()`
```c
static int timerslack_ns_show(struct seq_file *m, void *v)
{
  struct inode *inode = m->private;
  struct task_struct *p;
  int err = 0;

  p = get_proc_task(inode);
  if (!p)
    return -ESRCH;

  if (p != current) {
    rcu_read_lock();
    if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)) {
      rcu_read_unlock();
      err = -EPERM;
      goto out;
    }
    rcu_read_unlock();

    err = security_task_getscheduler(p);
    if (err)
      goto out;
  }

  task_lock(p);
  seq_printf(m, "%llu\n", p->timer_slack_ns);
  task_unlock(p);

out:
  put_task_struct(p);

  return err;
}
```
The core part is to get the corresponding `task_struct` then print it out, which is divided into three steps: `task_lock()` to prevent anyone from changing it, `seq_print()` to actually print that information and `task_unlock()` to release it. Therefore, our read function would be something like ~~(we do no checks lol)~~
```c
static int my_ctx_read(struct seq_file *m, void *v) {
  struct inode *inode = m->private;
  struct task_struct *p;

  p = get_proc_task(inode);
  if (!p) return -ESRCH;

  task_lock(p);
  seq_printf(m, "%llu\n", p->ctx);
  task_unlock(p);

  return 0;
}
```
And the wrapper would be
```c
static int my_ctx_open(struct inode *inode, struct file *flip) {
  return single_open(flip, my_ctx_read, inode);
}
```
Finally the file operations
```c
static const struct file_operations my_ctx_ops = {
  .open = my_ctx_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};
```
If all above are ready, go get some snacks and rest while the kernel compiles. When it’s done and rebooted, try `ctx` with this C code
```c
#include <stdio.h>
int main() {
  while(1) getchar();
  return 0;
}
```
`ctx` should increase every time a input is given.

{% include aligner.html images="posts/2021-04-22-linux-kernel-scheduling/result.png" column=1 %}