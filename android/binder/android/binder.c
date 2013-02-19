/* binder.c
 *
 * Android IPC Subsystem
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <asm/cacheflush.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/debugfs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "binder.h"

/*

		Linux系统中进程间通信的方式有:socket, named pipe,message queque, signal,share memory。Java系统中的进程间通信方式
	有socket, named pipe等，android应用程序理所当然可以应用JAVA的IPC机制实现进程间的通信，但我查看android的
	源码，在同一终端上的应用软件的通信几乎看不到这些IPC通信方式，取而代之的是Binder通信。Google为
	什么要采用这种方式呢，这取决于Binder通信方式的高效率。 Binder通信是通过linux的binder driver来实现的，
	Binder通信操作类似线程迁移(thread migration)，两个进程间IPC看起来就象是一个进程进入另一个进程执行代
	码然后带着执行的结果返回。Binder的用户空间为每一个进程维护着一个可用的线程池，线程池用于处
	理到来的IPC以及执行进程本地消息，Binder通信是同步而不是异步。
	
    		Android中的Binder通信是基于Service与Client的，所有需要IBinder通信的进程都必须创建一个IBinder接口，系统中
    	有一个进程管理所有的system service,Android不允许用户添加非授权的System service,当然现在源码开发了，我们
    	可以修改一些代码来实现添加底层system Service的目的。对用户程序来说，我们也要创建server,或者Service用
    	于进程间通信，这里有一个ActivityManagerService管理JAVA应用层所有的service创建与连接(connect),disconnect,所有的
    	Activity也是通过这个service来启动，加载的。ActivityManagerService也是加载在Systems Servcie中的。
    	
    		Android虚拟机启动之前系统会先启动service Manager进程，service Manager打开binder驱动，并通知binder kernel驱动程序
    	这个进程将作为System Service Manager，然后该进程将进入一个循环，等待处理来自其他进程的数据。用户
    	创建一个System service后，通过defaultServiceManager得到一个远程ServiceManager的接口，通过这个接口我们可以调用
    	addService函数将System service添加到Service Manager进程中，然后client可以通过getService获取到需要连接的目的Service的
    	IBinder对象，这个IBinder是Service的BBinder在binder kernel的一个参考，所以service IBinder 在binder kernel中不会存在相同的
    	两个IBinder对象，每一个Client进程同样需要打开Binder驱动程序。对用户程序而言，我们获得这个对象就可
    	以通过binder kernel访问service对象中的方法。Client与Service在不同的进程中，通过这种方式实现了类似线程间
    	的迁移的通信方式，对用户程序而言当调用Service返回的IBinder接口后，访问Service中的方法就如同调用自
    	己的函数。(  此段见Service_manager.c 的代码分析，目录为android\source\frameworks\base\cmds\servicemanager )

    	首先从ServiceManager 注册过程来逐步分析上述过程是如何实现的。见android\source\frameworks\base\cmds\servicemanager\Service_manager.c 的main 函数开始

*/



/*=======================================================
红黑树相关

struct rb_node
{
	struct rb_node *rb_parent;
	int rb_color;
	
	#define RB_RED 0
	#define RB_BLACK 1

	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct rb_root
{
	struct rb_node * rb_node;
};

#define RB_ROOT (struct rb_root) { NULL, }
#define rb_entry(ptr, type, member) container_of(ptr, type, member)

void rb_insert_color(struct rb_node *, struct rb_root *);
void rb_erase(struct rb_node *, struct rb_root *);

struct rb_node *rb_next(struct rb_node *);
struct rb_node *rb_prev(struct rb_node *);
struct rb_node *rb_first(struct rb_root *);
struct rb_node *rb_last(struct rb_root *);

void rb_replace_node(struct rb_node *victim,  struct rb_node *new, struct rb_root *root);

static inline void rb_link_node(struct rb_node * node,  struct rb_node * parent,  struct rb_node ** rb_link)
{
	node->rb_parent = parent;
	node->rb_color = RB_RED;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

*/

static DEFINE_MUTEX(binder_lock);
static DEFINE_MUTEX(binder_deferred_lock);

static HLIST_HEAD(binder_procs);
static HLIST_HEAD(binder_deferred_list);
static HLIST_HEAD(binder_dead_nodes);

static struct dentry *binder_debugfs_dir_entry_root; /* 见函数binder_init 中的操作，此值保存了binder 的目录项*/
static struct dentry *binder_debugfs_dir_entry_proc; /* 见函数binder_init 中的操作，此值保存了proc 文件系统中的binder 目录项，应该是/proc/binder/ */
static struct binder_node *binder_context_mgr_node; /* Service Manager 进程使用的node 结构*/
static uid_t binder_context_mgr_uid = -1; /* 用于保存Service Manager 进程的id */
static int binder_last_id;
static struct workqueue_struct *binder_deferred_workqueue;

#define BINDER_DEBUG_ENTRY(name) \
static int binder_##name##_open(struct inode *inode, struct file *file) \
{ \
	return single_open(file, binder_##name##_show, inode->i_private); \
} \
\
static const struct file_operations binder_##name##_fops = { \
	.owner = THIS_MODULE, \
	.open = binder_##name##_open, \
	.read = seq_read, \
	.llseek = seq_lseek, \
	.release = single_release, \
}

static int binder_proc_show(struct seq_file *m, void *unused);
BINDER_DEBUG_ENTRY(proc);

/* This is only defined in include/asm-arm/sizes.h */
#ifndef SZ_1K
#define SZ_1K                               0x400
#endif

#ifndef SZ_4M
#define SZ_4M                               0x400000
#endif

#define FORBIDDEN_MMAP_FLAGS                (VM_WRITE)

#define BINDER_SMALL_BUF_SIZE (PAGE_SIZE * 64)

enum 
{
	BINDER_DEBUG_USER_ERROR             = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION     = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION       = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE             = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER            = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION     = 1U << 5,
	BINDER_DEBUG_READ_WRITE             = 1U << 6,
	BINDER_DEBUG_USER_REFS              = 1U << 7,
	BINDER_DEBUG_THREADS                = 1U << 8,
	BINDER_DEBUG_TRANSACTION            = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE   = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER            = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS          = 1U << 12,
	BINDER_DEBUG_BUFFER_ALLOC           = 1U << 13,
	BINDER_DEBUG_PRIORITY_CAP           = 1U << 14,
	BINDER_DEBUG_BUFFER_ALLOC_ASYNC     = 1U << 15,
};


static uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR | BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION;

module_param_named(debug_mask, binder_debug_mask, uint, S_IWUSR | S_IRUGO);

static int binder_debug_no_lock;

module_param_named(proc_no_lock, binder_debug_no_lock, bool, S_IWUSR | S_IRUGO);

static DECLARE_WAIT_QUEUE_HEAD(binder_user_error_wait);

static int binder_stop_on_user_error;

static int binder_set_stop_on_user_error(const char *val,
					 struct kernel_param *kp)
{
	int ret;
	ret = param_set_int(val, kp);
	if (binder_stop_on_user_error < 2)
		wake_up(&binder_user_error_wait);
	
	return ret;
}

module_param_call(stop_on_user_error, binder_set_stop_on_user_error, param_get_int, &binder_stop_on_user_error, S_IWUSR | S_IRUGO);

#define binder_debug(mask, x...) \
	do { \
		if (binder_debug_mask & mask) \
			printk(KERN_INFO x); \
	} while (0)

#define binder_user_error(x...) \
	do { \
		if (binder_debug_mask & BINDER_DEBUG_USER_ERROR) \
			printk(KERN_INFO x); \
		if (binder_stop_on_user_error) \
			binder_stop_on_user_error = 2; \
	} while (0)

enum binder_stat_types 
{
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};

struct binder_stats 
{
	int br[_IOC_NR(BR_FAILED_REPLY) + 1];
	int bc[_IOC_NR(BC_DEAD_BINDER_DONE) + 1];
	int obj_created[BINDER_STAT_COUNT];
	int obj_deleted[BINDER_STAT_COUNT];
};

static struct binder_stats binder_stats;

static inline void binder_stats_deleted(enum binder_stat_types type)
{
	binder_stats.obj_deleted[type]++;
}

static inline void binder_stats_created(enum binder_stat_types type)
{
	binder_stats.obj_created[type]++;
}

struct binder_transaction_log_entry 
{
	int debug_id;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
};


struct binder_transaction_log 
{
	int next;
	int full;
	struct binder_transaction_log_entry entry[32];
};


static struct binder_transaction_log binder_transaction_log; 		/* 见数据结构binder_transaction_log 的定义*/
static struct binder_transaction_log binder_transaction_log_failed;

static struct binder_transaction_log_entry *binder_transaction_log_add(struct binder_transaction_log *log)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_transaction_log_entry *e;
	e = &log->entry[log->next];
	memset(e, 0, sizeof(*e));
	log->next++;
	
	if (log->next == ARRAY_SIZE(log->entry)) 
	{
		log->next = 0;
		log->full = 1;
	}
	return e;
}

struct binder_work 
{
	struct list_head entry;
	
	enum 
	{
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type;
};

struct binder_node /* binder 在驱动中实体*/
{
	int debug_id;
	struct binder_work work;
	
	union 
	{
		struct rb_node rb_node;
		struct hlist_node dead_node;
	};
	
	struct binder_proc *proc; /* 见函数binder_new_node 对其进行的赋值，实质赋的值为binder_open  中分配的内存*/
	struct hlist_head refs;
	
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	void __user *ptr; /* binder 对象的本地地址*/
	void __user *cookie;
	unsigned has_strong_ref:1;
	unsigned pending_strong_ref:1;
	unsigned has_weak_ref:1;
	unsigned pending_weak_ref:1;
	unsigned has_async_transaction:1;
	unsigned accept_fds:1;
	unsigned min_priority:8;
	struct list_head async_todo;
};

struct binder_ref_death 
{
	struct binder_work work;
	void __user *cookie;
};

struct binder_ref 
{
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	int debug_id;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct hlist_node node_entry;
	struct binder_proc *proc;
	struct binder_node *node;
	uint32_t desc; /* binder 对象的远程索引。如果是Service Manager 的node 此值为0，其他的node 此值为大于0 的，此值对应于handle ，见函数binder_get_ref_for_node 中的处理*/
	int strong;
	int weak;
	struct binder_ref_death *death;
};

struct binder_buffer 
{
	struct list_head entry; /* free and allocated entries by addesss */
	struct rb_node rb_node; /* free entry by size or allocated entry */
				/* by address */
	unsigned free:1;
	unsigned allow_user_free:1;
	unsigned async_transaction:1;
	unsigned debug_id:29;

	struct binder_transaction *transaction;

	struct binder_node *target_node;
	size_t data_size;
	size_t offsets_size;
	uint8_t data[0];
};

enum binder_deferred_state 
{
	BINDER_DEFERRED_PUT_FILES    = 0x01,
	BINDER_DEFERRED_FLUSH        = 0x02,
	BINDER_DEFERRED_RELEASE      = 0x04,
};

struct binder_proc 
{
	struct hlist_node proc_node;
	struct rb_root threads; /* 此进程的所有线程红黑树的根，根据相关代码(binder_get_thread) 的分析可初步判断节点数据结构binder_thread 在通过域成员rb_node 插入到此红黑树中时是以binder_thread 的域成员pid 为顺序的*/
	struct rb_root nodes;	/* 节点红黑树的根，根据相关代码(binder_new_node) 的分析可初步判断节点数据结构binder_node 在通过域成员rb_node 插入到此红黑树中时是以binder_node 的域成员ptr 为顺序的*/
	struct rb_root refs_by_desc;/* 红黑树的根，根据相关代码(binder_get_ref_for_node) 的分析可初步判断数据结构binder_ref 在通过域成员rb_node_desc 插入到此红黑树中时是以binder_ref 的域成员desc 为顺序的*/
	struct rb_root refs_by_node;/* 红黑树的根，根据相关代码(binder_get_ref_for_node) 的分析可初步判断数据结构binder_ref 在通过域成员rb_node_node 插入到此红黑树中时是以binder_ref 的域成员node 为顺序的*/

	int pid; /* 在函数binder_open 中被赋值为current->group_leader->pid，即线程组长的pid */
	
	struct vm_area_struct *vma; /* 见函数binder_mmap 对其进行的赋值*/
	struct task_struct *tsk; /* 见函数binder_open 对其进行的赋值，指向调用binder_open  的线程的task struct  数据结构*/
	struct files_struct *files; /* 见函数binder_mmap 对其进行的赋值*/
	
	struct hlist_node deferred_work_node;
	int deferred_work;
	void *buffer;
	/*
		用户需要映射的虚拟起始地址为vma->vm_start，虚拟结束地址为vma->vm_end，而经过函数
		get_vm_area 的调用后获得到的虚拟起始地址为area->addr，具体见linux 内核学习笔记中对此
		函数的分析( 初步分析调用函数get_vm_area 只是传入了要分配的虚拟空间的大小，所以
		函数内部就会根据这个空间的大小在全局虚拟地址数据结构链表中找到合适的地方
		，然后分配一个虚拟数据结构，并按照链表中的所有虚拟地址的排序等确定虚拟数据
		结构中的起始地址，即area->addr) 。所以映射的虚拟地址和分配后的起始地址，
		即vma->vm_start 与area->addr 会存在一定的偏差，所以proc->user_buffer_offset 就是用于保存此值的
	*/
	ptrdiff_t user_buffer_offset; /* 见函数binder_mmap 中的分析及赋值*/

	struct list_head buffers; /* */
	/* 
		free 和alloced 分别代表两个红黑树，管理buffer 空间的，相当于所有的buffer 空间都
		是存在已经分配好的，只是在free 和alloced 两个红黑树之间进行转换。那么buffer 的
		分配是在哪里呢，答案是在函数binder_mmap 中进行的
		
		如果一个binder_buffer 被执行释放动作则将其从alloced 树中删除，插入到free 树中
		如果一个binder_buffer 被执行分配动作则将其从free 树中删除，插入到alloced 树中
	*/
	struct rb_root free_buffers; /* 红黑树的根，根据相关代码(binder_insert_free_buffer) 的分析可初步判断数据结构binder_buffer 在通过域成员rb_node 插入到此红黑树中时是以binder_buffer 中代表buffer 的大小为顺序的*/
	struct rb_root allocated_buffers; /* 红黑树的根，根据相关代码(binder_insert_allocated_buffer) 的分析可初步判断数据结构binder_buffer 在通过域成员rb_node 插入到此红黑树中时是以binder_buffer 本身的地址为顺序的*/
	size_t free_async_space;

	struct page **pages; 	/* 	此为一个指针数组，此数组的内存分配在函数binder_mmap 中实现的。
							见函数binder_update_page_range 中的代码分析，此为一个指针数组，数组中的
							每个单元都指向一个实际的物理页面，即每个单元都指向一个真
							正的数据buffer 分配的一个物理页面
						*/
	size_t buffer_size;
	uint32_t buffer_free;
	struct list_head todo;
	wait_queue_head_t wait;
	struct binder_stats stats;
	struct list_head delivered_death;
	int max_threads;	/* 见函数binder_ioctl 中的BINDER_SET_MAX_THREADS 命令调用的赋值，用于设定线程池的数量*/
	int requested_threads;
	int requested_threads_started;
	int ready_threads;
	long default_priority;
	struct dentry *debugfs_entry;
};

enum 
{
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	BINDER_LOOPER_STATE_EXITED      = 0x04,
	BINDER_LOOPER_STATE_INVALID     = 0x08,
	BINDER_LOOPER_STATE_WAITING     = 0x10,
	BINDER_LOOPER_STATE_NEED_RETURN = 0x20
};

struct binder_thread 
{
	struct binder_proc *proc;
	struct rb_node rb_node;
	int pid; /* 在函数binder_get_thread 中被赋值为current->pid，调用函数的那个线程的pid，不是线程组长的pid (proc->pid) */
	int looper;
	struct binder_transaction *transaction_stack; /* transaction 的一个堆栈，相当于发送给本进程需要处理的都放在这个队列中*/
	struct list_head todo;
	uint32_t return_error; /* Write failed, return error code in read buf */
	uint32_t return_error2; /* Write failed, return error code in read */
		/* buffer. Used when sending a reply to a dead process that */
		/* we are also waiting on */
	wait_queue_head_t wait;
	struct binder_stats stats;
};

struct binder_transaction 
{
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	unsigned need_reply:1;
	/* unsigned is_dead:1; */	/* not used at the moment */

	struct binder_buffer *buffer;
	unsigned int	code;
	unsigned int	flags;
	long	priority;
	long	saved_priority;
	uid_t	sender_euid;
};

static void binder_defer_work(struct binder_proc *proc, enum binder_deferred_state defer);

/*
 * copied from get_unused_fd_flags
 */
int task_get_unused_fd_flags(struct binder_proc *proc, int flags)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct files_struct *files = proc->files;
	int fd, error;
	struct fdtable *fdt;
	unsigned long rlim_cur;
	unsigned long irqs;

	if (files == NULL)
		return -ESRCH;

	error = -EMFILE;
	spin_lock(&files->file_lock);

repeat:
	fdt = files_fdtable(files);
	fd = find_next_zero_bit(fdt->open_fds->fds_bits, fdt->max_fds, files->next_fd);

	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	rlim_cur = 0;
	if (lock_task_sighand(proc->tsk, &irqs)) 
	{
		rlim_cur = proc->tsk->signal->rlim[RLIMIT_NOFILE].rlim_cur;
		unlock_task_sighand(proc->tsk, &irqs);
	}
	
	if (fd >= rlim_cur)
		goto out;

	/* Do we need to expand the fd array or fd set?  */
	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	if (error) 
	{
		/*
		 * If we needed to expand the fs array we
		 * might have blocked - try again.
		 */
		error = -EMFILE;
		goto repeat;
	}

	FD_SET(fd, fdt->open_fds);
	if (flags & O_CLOEXEC)
		FD_SET(fd, fdt->close_on_exec);
	else
		FD_CLR(fd, fdt->close_on_exec);
	
	files->next_fd = fd + 1;
#if 1
	/* Sanity check */
	if (fdt->fd[fd] != NULL)
	{
		printk(KERN_WARNING "get_unused_fd: slot %d not NULL!\n", fd);
		fdt->fd[fd] = NULL;
	}
#endif
	error = fd;

out:
	spin_unlock(&files->file_lock);
	return error;
}

/*
 * copied from fd_install
 */
static void task_fd_install(struct binder_proc *proc, unsigned int fd, struct file *file)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct files_struct *files = proc->files;
	struct fdtable *fdt;

	if (files == NULL)
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	spin_unlock(&files->file_lock);
}

/*
 * copied from __put_unused_fd in open.c
 */
static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__FD_CLR(fd, fdt->open_fds);
	
	if (fd < files->next_fd)
		files->next_fd = fd;
}

/*
 * copied from sys_close
 */
static long task_close_fd(struct binder_proc *proc, unsigned int fd)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct file *filp;
	struct files_struct *files = proc->files;
	struct fdtable *fdt;
	int retval;

	if (files == NULL)
		return -ESRCH;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	
	if (fd >= fdt->max_fds)
		goto out_unlock;
	
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	retval = filp_close(filp, files);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||retval == -ERESTARTNOINTR ||retval == -ERESTARTNOHAND ||retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

static void binder_set_nice(long nice)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	long min_nice;
	if (can_nice(current, nice)) 
	{
		set_user_nice(current, nice);
		return;
	}
	
	min_nice = 20 - current->signal->rlim[RLIMIT_NICE].rlim_cur;
	binder_debug(BINDER_DEBUG_PRIORITY_CAP, "binder: %d: nice value %ld not allowed use " "%ld instead\n", current->pid, nice, min_nice);

	set_user_nice(current, min_nice);
	if (min_nice < 20)
		return;
	
	binder_user_error("binder: %d RLIMIT_NICE not set\n", current->pid);
}

static size_t binder_buffer_size(struct binder_proc *proc,  struct binder_buffer *buffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、返回参数buffer 中的buffer 空间的大小
		2、图示说明

			-----------------------------------------------------------------------------------------------------------------------------
			|binder_buffer 结构1	|XXXXXXXXXXXXXXXXXXXXXXXX|binder_buffer 结构2|XXXXXXXXXXXXXX|binder_buffer 结构3|XXXXXXXXXXXXXXXX|
			-----------------------------------------------------------------------------------------------------------------------------
			|																															|
			|																															|
			|																															|
			start																															end
			

			图示为一个连续的地址空间内的数据内容，其中XXXXX 为数据空间，从start 到end 为函数
			binder_mmap 中传下来的用户映射的起始和结束地址。所以通过binder_mmap 的代码可知
				proc -> buffer  		= start;
				proc -> buffer_size	= end;
			
			图示可见，整个地址空间内容是由多个binder_buffer 结构来管理的，所有的binder_buffer 结构
			由一个链表来管理( 由proc 的域成员buffers 来保存链表)。因此获得一个binder_buffer 的buffer 大
			小就是获取其所管理的XXXXX  空间的大小

			
			binder_buffer 数据结构中的最后一个域成员data[0]，所以 binder_buffer ->data 为一个地址值，即其
			所管理的XXXX 空间的起始地址。

			由上述的分析便可知此函数的获取原理了，有两种情况
			
			1、传入的buffer 为整个空间中最后一个binder_buffer 数据结构
				size 	= end - buffer->data 
					= (proc->buffer + proc->buffer_size) - (buffer->data)
					
			2、传入的buffer 不是整个空间中最后一个binder_buffer 数据结构
				size	= ( 后一个binder_buffer 结构的起始地址) - ( 传入binder_buffer 数据结构的数据起始地址)
					= list_entry(buffer->entry.next, struct binder_buffer, entry) - (buffer->data)
			
*/
	if (list_is_last(&buffer->entry, &proc->buffers))
		return proc->buffer + proc->buffer_size - (void *)buffer->data;
	else
		return (size_t)list_entry(buffer->entry.next, struct binder_buffer, entry) - (size_t)buffer->data;
}

static void binder_insert_free_buffer(struct binder_proc *proc, struct binder_buffer *new_buffer)
{
/*
	参数:
		1、proc			: 传入由open 函数分配的内存数据结构
		2、new_buffer	: 传入一个binder_buffer 的地址指针
		
	返回:
		1、
		
	说明:
		1、此函数的执行过程
			A、首先在proc 的域成员free_buffers 为根的红黑树中查找，确定传入
				的参数应该插入的位置( 以binder_buffer 中所代表的buffer 大小为顺序插入)
			B、将传入的参数new_buffer 所指向的binder_buffer 插入到proc 的域成员
				free_buffers 为根的红黑树中
*/
	struct rb_node **p = &proc->free_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;
	size_t buffer_size;
	size_t new_buffer_size;

	BUG_ON(!new_buffer->free);

	new_buffer_size = binder_buffer_size(proc, new_buffer);

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: add free buffer, size %zd, "  "at %p\n", proc->pid, new_buffer_size, new_buffer);

	while (*p) 
	{
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);

		buffer_size = binder_buffer_size(proc, buffer);

		if (new_buffer_size < buffer_size)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->free_buffers);
}

static void binder_insert_allocated_buffer(struct binder_proc *proc, struct binder_buffer *new_buffer)
{
/*
	参数:
		1、proc			: 传入由open 函数分配的内存数据结构
		2、new_buffer	: 传入一个binder_buffer 的地址指针
		
	返回:
		1、
		
	说明:
		1、此函数的执行过程
			A、首先在proc 的域成员allocated_buffers 为根的红黑树中查找，确定传入
				的参数应该插入的位置( 以binder_buffer 本身的地址为顺序插入，参考binder_buffer_size 函数说明)
			B、将传入的参数new_buffer 所指向的binder_buffer 插入到proc 的域成员
				allocated_buffers 为根的红黑树中
*/
	struct rb_node **p = &proc->allocated_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;

	BUG_ON(new_buffer->free);

	while (*p) 
	{
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (new_buffer < buffer)
			p = &parent->rb_left;
		else if (new_buffer > buffer)
			p = &parent->rb_right;
		else
			BUG();
	}
	
	rb_link_node(&new_buffer->rb_node, parent, p);/* 插入到红黑树中*/
	rb_insert_color(&new_buffer->rb_node, &proc->allocated_buffers);/* 更新红黑树中刚插入节点的颜色*/
}

static struct binder_buffer *binder_buffer_lookup(struct binder_proc *proc, void __user *user_ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、见函数binder_buffer_size 中的说明可知，传入的用户user_ptr  指针实质就是XXXX 空间的地址经转换后给
			用户的值，而在proc 的域成员allocated_buffers 所维护的已分配buffer 的红黑树中以binder_buffer 数据结构的
			起始地址来排序的，所以需要将传入的user_ptr 地址转换为对应的binder_buffer 数据结构的起始地址
			(  参考binder_buffer_size 函数说明)
			
		2、此函数的执行过程
			A、首先在proc 的域成员allocated_buffers 为根的红黑树中查找与参数user_ptr 经过换算后相 匹配的
				buffer，如果找到就返回此buffer
*/
	struct rb_node *n = proc->allocated_buffers.rb_node;
	struct binder_buffer *buffer;
	struct binder_buffer *kern_ptr;

	kern_ptr = user_ptr - proc->user_buffer_offset - offsetof(struct binder_buffer, data);

	while (n)
	{
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (kern_ptr < buffer)
			n = n->rb_left;
		else if (kern_ptr > buffer)
			n = n->rb_right;
		else
			return buffer;
	}
	return NULL;
}

static int binder_update_page_range(struct binder_proc *proc, int allocate, void *start, void *end, struct vm_area_struct *vma)
{
/*
	参数:
		1、proc		: 传入由open 函数分配的内存数据结构
		2、allocate	: 传入是否为分配标志，如果为0 表示要释放空间及断开页式映射，1 则为分配实际的空间并建立页式映射
		3、start		: 传入起始地址(  虚地址，此值为经过get_vm_area 函数执行返回的vm_struct -> addr 的值，此值与用户的地址存在一定的偏差，见proc 的域成员user_buffer_offset 的说明)
		4、end		: 传入结束地址(  见start 的说明，相类似)
		5、vma		: 传入一个vm_area_struct 数据结构，如果此值为空就会使用调用binder_mmap 时传入的vma 数据结构，见代码
		
	返回:
		1、
		
	说明:
		1、此函数内才真正的实现了为起始地址到结束地址之间的虚地址分配内存空间，并
			对其实现页面映射的过程。
		2、函数的执行过程:
			A、对传入的参数进行校验( 结束地址是否在起始地址之后)
			B、根据起始地址、结束地址进行实际的内存分配，并将分配得到的每个内存
				页面地址保存到proc 数据结构的pages 域成员的数组中
				分配真正的物理内存时是按照页为单位大小操作的
			C、对每个分配的物理页面进行页式映射等操作
			D、同时将更新用户的vm 数据结构中的地址信息
*/
	void *page_addr;
	unsigned long user_page_addr;
	struct vm_struct tmp_area;
	struct page **page;
	struct mm_struct *mm;

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: %s pages %p-%p\n", proc->pid, allocate ? "allocate" : "free", start, end);

	if (end <= start) /* 参数校验*/
		return 0;

	if (vma)
		mm = NULL;
	else
		mm = get_task_mm(proc->tsk);

	if (mm)
	{
		down_write(&mm->mmap_sem);
		vma = proc->vma; /* 取出函数binder_mmap 中传入的vma 数据结构*/
	}

	if (allocate == 0) /* 释放空间*/
		goto free_range;

	if (vma == NULL) 
	{
		printk(KERN_ERR "binder: %d: binder_alloc_buf failed to " "map pages in userspace, no vma\n", proc->pid);
		goto err_no_vma;
	}

	for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) 
	{
		int ret;
		struct page **page_array_ptr;

		/*
			获取一个proc 的域成员pages 的数组中的一个元素( 用于保存实际的物理页面地址)
		*/
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];

		BUG_ON(*page);
		
		/* 
			分配真正的物理内存空间，并将分配得到的物理页面地
			址保存到proc 的域成员pages 的数组中
		*/
		*page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (*page == NULL) 
		{
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed ""for page at %p\n", proc->pid, page_addr);
			goto err_alloc_page_failed;
		}
		
		tmp_area.addr = page_addr;

		/* 
			见linux 学习笔记中可知，函数map_vm_area 中会首先对tmp_area->size 的值执行减去一
			个PAGE_SIZE 的操作来计算结束地址的，所以此处需要加上一个PAGE_SIZE 的值
		*/
		tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */; 
		page_array_ptr = page;

		/*
			对上面刚刚分配的物理页面进行页式映射等操作
			即将分配的页面地址与虚拟地址进行映射
		*/
		ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
		if (ret) 
		{
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed " "to map page at %p in kernel\n", proc->pid, page_addr);
			goto err_map_kernel_failed;
		}

		/* 获得到用户的页面起始地址*/
		user_page_addr = (uintptr_t)page_addr + proc->user_buffer_offset;

		/* 将操作后的地址，即经过页式映射后又转换为用户的地址插入到vma 数据结构中*/
		ret = vm_insert_page(vma, user_page_addr, page[0]);
		if (ret) 
		{
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "  "to map page at %lx in userspace\n", proc->pid, user_page_addr);
			goto err_vm_insert_page_failed;
		}
		/* vm_insert_page does not seem to increment the refcount */
	}
	
	if (mm) 
	{
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return 0;

free_range:
	for (page_addr = end - PAGE_SIZE; page_addr >= start; page_addr -= PAGE_SIZE) 
	{
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
		
		if (vma)
			zap_page_range(vma, (uintptr_t)page_addr + proc->user_buffer_offset, PAGE_SIZE, NULL);
		
err_vm_insert_page_failed:
		unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
		
err_map_kernel_failed:
		__free_page(*page);
		*page = NULL;
		
err_alloc_page_failed:
		;
	}
	
err_no_vma:
	if (mm) 
	{
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return -ENOMEM;
}

static struct binder_buffer *binder_alloc_buf(struct binder_proc *proc,  size_t data_size,  size_t offsets_size, int is_async)
{
/*
	参数:
		1、proc			: 传入由open 函数分配的内存数据结构
		2、data_size		: 传入data 的大小
		3、offsets_size	: 传入offset 的大小
		4、is_async		: 
		
	返回:
		1、
		
	说明:
		1、说明(  最好结合binder_buffer_size 函数的说明)
		
			分配前空间示意图:
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|binder_buffer 结构1	|XXXXXX|binder_buffer 结构2|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |binder_buffer 结构3|XXXXX|binder_buffer 结构4|XXXX|
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|												|									  							|													|
					|												|									  							|													|
					|												xxx									  							yyy													|
					start																																									end

			假设: 
					xxx ~~ yyy 的空间没有进行物理页面的分配，即没有进行
					页面映射，体现在结构2 的域成员中free=0
					
					binder_buffer 结构1 的XXXX 空间大小为1K;
					binder_buffer 结构2 的XXXX 空间大小为4K;
					binder_buffer 结构3 的XXXX 空间大小为2K;
					binder_buffer 结构4 的XXXX 空间大小为5K;

			条件:
					用户需要申请的空间大小为(data_size+offsets_size) 3K

			查找:
					遍历binder_buffer 的红黑树可以找到最适合的应该是binder_buffer 结构2 

			分配:
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|binder_buffer 结构1	|XXXXXX|binder_buffer 结构2|XXXXXXXXXXXXXXXXXXXX |binder_buffer 结构5|XXXXXXXXXXXXXXXX |binder_buffer 结构3|XXXXX|binder_buffer 结构4|XXXX|
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|												|						 |	   				|		     			|													|
					|												|						 |	   				|		     			|													|
					|												xxx						 aa	   				bb		      			yyy													|
					start																																									end

			结果:
					函数中经过对空闲buffer  的查找，结果找到结构2 所管理的空间适合分配用户，但
					结构2 管理的空间又大于用户需要的( 没有正好的)，所以将结构2 管理的空间进行
					拆分分配，即代码中实现了将aa ~~ cc 的空间进行了物理内存的分配并建立页面映
					射，xxx ~~ aa 的空间为3k ，正好分配给用户，由结构2 管理，即此函数返回结构2
					的地址。aa ~~ bb 为一个binder_buffer 数据结构的空间，即结构5 的内存空间，分配此空
					间的目的就是为了对拆分后的bb ~~ yyy 的一段地址进行管理。即理解为原来整个的
					xxx ~~ yyy 的空间都是有结构2 来管理的，现在经过拆分之后结构2 只管理了xxx ~~ aaa
					的空间，那么剩下的空间怎么办，所以就在剩下的空间中分配了一个结构5，然
					后让结构5 对bb ~~ yyy 进行管理，函数中真正分配的内存空间为xxx ~~ bb

					( 上述的分析是用户申请的空间为3k，没有正好的buffer 可用，如果用户申请的正好
					是4k 的空间，则结构2 所管理的空间正好，那么就直接对xxx ~~ yyy 的地址进行物理
					页面的分配及页式映射就可以了，然后返回结构2 的地址)

					经过上述分析，此函数真正实现的内存分配及页式映射的空间为xxx ~~ bb
					
					binder_buffer 结构1 的XXXX 空间大小为1K;
					binder_buffer 结构2 的XXXX 空间大小为3K [xxx~~aa];  // --- 分配给用户使用了
					binder_buffer 结构5 的XXXX 空间大小为1K-sizeof(struct binder_buffer) [bb~~yyy];
					binder_buffer 结构3 的XXXX 空间大小为2K;
					binder_buffer 结构4 的XXXX 空间大小为5K;
*/

	struct rb_node *n = proc->free_buffers.rb_node; 
	struct binder_buffer *buffer;
	size_t buffer_size;
	struct rb_node *best_fit = NULL;
	void *has_page_addr;
	void *end_page_addr;
	size_t size;

	if (proc->vma == NULL) 
	{
		printk(KERN_ERR "binder: %d: binder_alloc_buf, no vma\n", proc->pid);
		return NULL;
	}

	/* 计算data 和offset 两个size 的总和*/
	size = ALIGN(data_size, sizeof(void *)) + ALIGN(offsets_size, sizeof(void *));

	if (size < data_size || size < offsets_size) 
	{
		binder_user_error("binder: %d: got transaction with invalid ""size %zd-%zd\n", proc->pid, data_size, offsets_size);
		return NULL;
	}

	if (is_async &&  proc->free_async_space < size + sizeof(struct binder_buffer)) 
	{
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_alloc_buf size %zd" "failed, no async space left\n", proc->pid, size);
		return NULL;
	}

	/* 根据总共需要申请的空间大小在空闲红黑树中找到合适的buffer 结构*/
	while (n) 
	{
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		buffer_size = binder_buffer_size(proc, buffer);

		if (size < buffer_size) 
		{
			best_fit = n;
			n = n->rb_left;
		} 
		else if (size > buffer_size)
			n = n->rb_right;
		else 
		{
			best_fit = n;
			break;
		}
	}

	/*
		注意上面的循环	
			如果找到size == buffer_size 的buffer 的话，则n != NULL;
			如果没找到size == buffer_size 的buffer 的话，即size < buffer_size，则n = NULL;
	*/
	
	if (best_fit == NULL) 
	{
		printk(KERN_ERR "binder: %d: binder_alloc_buf size %zd failed, " "no address space\n", proc->pid, size);
		return NULL;
	}
	
	if (n == NULL)  /* n==NULL 表示一定是找到了一个size < buffer_size 的buffer */
	{
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		buffer_size = binder_buffer_size(proc, buffer);
	}

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_alloc_buf size %zd got buff" "er %p size %zd\n", proc->pid, size, buffer, buffer_size);

	has_page_addr = (void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
	if (n == NULL) /* n==NULL 表示一定是找到了一个size < buffer_size 的buffer */
	{
		/* 
			修正真正要分配的物理页面的空间大小，即用户要申请的大
			小加上一个binder_buffer 结构的大小，见上面说明
		*/
		if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
			buffer_size = size; /* no room for other buffers */
		else
			buffer_size = size + sizeof(struct binder_buffer);
	}
	
	end_page_addr = (void *)PAGE_ALIGN((uintptr_t)buffer->data + buffer_size);
	
	if (end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;

	/* 对找到的buffer 数据结构中的起始地址到结束地址之间的虚拟地址进行实际的内存页面分配，并建立相应的页式映射*/
	if (binder_update_page_range(proc, 1, (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr, NULL))
		return NULL;

	rb_erase(best_fit, &proc->free_buffers);
	buffer->free = 0;
	/* 将刚分配的buffer 插入到已分配的buffer 红黑树中*/
	binder_insert_allocated_buffer(proc, buffer); /* 见函数内部*/

	/* 
		如果找到的buffer 所代表的空间大小与需要分配的空间大小不相等，则说
		明原有的空间大，需要的空间小，因此将剩余的部分再重新进行管理

		见说明的binder_buffer 结构5 的生成，如果binder_buffer 结构2 的空间正好满足用户
		申请的大小，就不会有binder_buffer 结构5 的产生
	*/
	if (buffer_size != size)
	{
		struct binder_buffer *new_buffer = (void *)buffer->data + size;
		list_add(&new_buffer->entry, &buffer->entry);
		new_buffer->free = 1;
		binder_insert_free_buffer(proc, new_buffer);
	}
	
	binder_debug(BINDER_DEBUG_BUFFER_ALLOC,"binder: %d: binder_alloc_buf size %zd got "  "%p\n", proc->pid, size, buffer);

	buffer->data_size = data_size;
	buffer->offsets_size = offsets_size;
	buffer->async_transaction = is_async;
	
	if (is_async)
	{
		proc->free_async_space -= size + sizeof(struct binder_buffer);
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC_ASYNC, "binder: %d: binder_alloc_buf size %zd " "async free %zd\n", proc->pid, size, proc->free_async_space);
	}

	return buffer;
}

static void *buffer_start_page(struct binder_buffer *buffer)
{
	return (void *)((uintptr_t)buffer & PAGE_MASK);
}

static void *buffer_end_page(struct binder_buffer *buffer)
{
	return (void *)(((uintptr_t)(buffer + 1) - 1) & PAGE_MASK);
}

static void binder_delete_free_buffer(struct binder_proc *proc, struct binder_buffer *buffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_buffer *prev, *next = NULL;
	int free_page_end = 1;
	int free_page_start = 1;

	BUG_ON(proc->buffers.next == &buffer->entry);
	prev = list_entry(buffer->entry.prev, struct binder_buffer, entry);
	BUG_ON(!prev->free);
	
	if (buffer_end_page(prev) == buffer_start_page(buffer)) 
	{
		free_page_start = 0;
		if (buffer_end_page(prev) == buffer_end_page(buffer))
			free_page_end = 0;
		
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: merge free, buffer %p " "share page with %p\n", proc->pid, buffer, prev);
	}

	if (!list_is_last(&buffer->entry, &proc->buffers))
	{
		next = list_entry(buffer->entry.next, struct binder_buffer, entry);
		if (buffer_start_page(next) == buffer_end_page(buffer)) 
		{
			free_page_end = 0;
			if (buffer_start_page(next) == buffer_start_page(buffer))
				free_page_start = 0;
			
			binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: merge free, buffer" " %p share page with %p\n", proc->pid,  buffer, prev);
		}
	}
	
	list_del(&buffer->entry);
	
	if (free_page_start || free_page_end)
	{
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: merge free, buffer %p do " "not share page%s%s with with %p or %p\n", proc->pid, buffer, free_page_start ? "" : " end", free_page_end ? "" : " start", prev, next);
		
		binder_update_page_range(proc, 0, free_page_start ? buffer_start_page(buffer) : buffer_end_page(buffer), (free_page_end ? buffer_end_page(buffer) : buffer_start_page(buffer)) + PAGE_SIZE, NULL);
	}
}

static void binder_free_buf(struct binder_proc *proc, struct binder_buffer *buffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、执行过程:
			A、首先将传入参数buffer 从proc 的域成员allocated_buffers 所代表的红黑树中删除
			B、将释放后的buffer 插入到proc 的域成员free_buffers 所代表的红黑树中
*/
	size_t size, buffer_size;

	buffer_size = binder_buffer_size(proc, buffer);

	size = ALIGN(buffer->data_size, sizeof(void *)) + ALIGN(buffer->offsets_size, sizeof(void *));

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_free_buf %p size %zd buffer"  "_size %zd\n", proc->pid, buffer, size, buffer_size);

	BUG_ON(buffer->free);
	BUG_ON(size > buffer_size);
	BUG_ON(buffer->transaction != NULL);
	BUG_ON((void *)buffer < proc->buffer);
	BUG_ON((void *)buffer > proc->buffer + proc->buffer_size);

	if (buffer->async_transaction)
	{
		proc->free_async_space += size + sizeof(struct binder_buffer);

		binder_debug(BINDER_DEBUG_BUFFER_ALLOC_ASYNC,"binder: %d: binder_free_buf size %zd " "async free %zd\n", proc->pid, size,proc->free_async_space);
	}

	binder_update_page_range(proc, 0,(void *)PAGE_ALIGN((uintptr_t)buffer->data),(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK),NULL);
	
	rb_erase(&buffer->rb_node, &proc->allocated_buffers);
	buffer->free = 1;
	
	if (!list_is_last(&buffer->entry, &proc->buffers)) 
	{
		struct binder_buffer *next = list_entry(buffer->entry.next, struct binder_buffer, entry);
		if (next->free) 
		{
			rb_erase(&next->rb_node, &proc->free_buffers);
			binder_delete_free_buffer(proc, next);
		}
	}
	if (proc->buffers.next != &buffer->entry) 
	{
		struct binder_buffer *prev = list_entry(buffer->entry.prev,struct binder_buffer, entry);
		if (prev->free)
		{
			binder_delete_free_buffer(proc, buffer);
			rb_erase(&prev->rb_node, &proc->free_buffers);
			buffer = prev;
		}
	}
	binder_insert_free_buffer(proc, buffer);
}

static struct binder_node *binder_get_node(struct binder_proc *proc,  void __user *ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数实现了根据参数ptr 在proc 的域成员nodes 所代表的红黑树
			中查找，如果找到就返回，否则返回空
*/
	struct rb_node *n = proc->nodes.rb_node;
	struct binder_node *node;

	while (n) 
	{
		node = rb_entry(n, struct binder_node, rb_node);

		if (ptr < node->ptr)
			n = n->rb_left;
		else if (ptr > node->ptr)
			n = n->rb_right;
		else
			return node;
	}
	return NULL;
}

static struct binder_node *binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、创建或者查找一个binder  的实体
		2、此函数的执行过程
			A、首先在proc 的域成员nodes 为根的红黑树中查找与参数ptr 匹配的
				节点，如果找到就返回此节点
			B、经过A  步骤没找到，则此时分配一个节点的内存空间，同时对
				新分配的节点进行相应的初始化，并通过节点中的rb_node 域成员
				将此节点插入到proc 的域成员nodes 为根的红黑树中
*/
	struct rb_node **p = &proc->nodes.rb_node;
	struct rb_node *parent = NULL;
	struct binder_node *node;

	while (*p) 
	{
		parent = *p;
		node = rb_entry(parent, struct binder_node, rb_node);

		if (ptr < node->ptr)
			p = &(*p)->rb_left;
		else if (ptr > node->ptr)
			p = &(*p)->rb_right;
		else
			return NULL;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return NULL;
	
	binder_stats_created(BINDER_STAT_NODE);
	
	rb_link_node(&node->rb_node, parent, p); /* 通过节点中的rb_node 域成员将其连入到proc 的nodes 域成员的红黑树中*/
	rb_insert_color(&node->rb_node, &proc->nodes);
	
	node->debug_id = ++binder_last_id;
	node->proc = proc;
	node->ptr = ptr;
	node->cookie = cookie;
	node->work.type = BINDER_WORK_NODE;
	INIT_LIST_HEAD(&node->work.entry);
	INIT_LIST_HEAD(&node->async_todo);
	
	binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d:%d node %d u%p c%p created\n", proc->pid, current->pid, node->debug_id, node->ptr, node->cookie);
	return node;
}

static int binder_inc_node(struct binder_node *node, int strong, int internal, struct list_head *target_list)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (strong) 
	{
		if (internal) 
		{
			if (target_list == NULL && node->internal_strong_refs == 0 &&  !(node == binder_context_mgr_node && node->has_strong_ref)) 
			{
				printk(KERN_ERR "binder: invalid inc strong ""node for %d\n", node->debug_id);
				return -EINVAL;
			}
			node->internal_strong_refs++;
		}
		else
			node->local_strong_refs++;
		
		if (!node->has_strong_ref && target_list) 
		{
			list_del_init(&node->work.entry);
			list_add_tail(&node->work.entry, target_list);
		}
	} 
	else 
	{
		if (!internal)
			node->local_weak_refs++;
		
		if (!node->has_weak_ref && list_empty(&node->work.entry)) 
		{
			if (target_list == NULL) 
			{
				printk(KERN_ERR "binder: invalid inc weak node ""for %d\n", node->debug_id);
				return -EINVAL;
			}
			
			list_add_tail(&node->work.entry, target_list);
		}
	}
	return 0;
}

static int binder_dec_node(struct binder_node *node, int strong, int internal)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (strong) 
	{
		if (internal)
			node->internal_strong_refs--;
		else
			node->local_strong_refs--;
		if (node->local_strong_refs || node->internal_strong_refs)
			return 0;
	} 
	else 
	{
		if (!internal)
			node->local_weak_refs--;
		if (node->local_weak_refs || !hlist_empty(&node->refs))
			return 0;
	}
	if (node->proc && (node->has_strong_ref || node->has_weak_ref))
	{
		if (list_empty(&node->work.entry)) 
		{
			list_add_tail(&node->work.entry, &node->proc->todo);
			wake_up_interruptible(&node->proc->wait);
		}
	} 
	else 
	{
		if (hlist_empty(&node->refs) && !node->local_strong_refs &&  !node->local_weak_refs) 
		{
			list_del_init(&node->work.entry);
			
			if (node->proc)
			{
				rb_erase(&node->rb_node, &node->proc->nodes);
				binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: refless node %d deleted\n", node->debug_id);
			} 
			else 
			{
				hlist_del(&node->dead_node);
				binder_debug(BINDER_DEBUG_INTERNAL_REFS,"binder: dead node %d deleted\n",node->debug_id);
			}
			kfree(node);
			binder_stats_deleted(BINDER_STAT_NODE);
		}
	}

	return 0;
}


static struct binder_ref *binder_get_ref(struct binder_proc *proc, uint32_t desc)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数实现了根据参数desc 在proc 的域成员refs_by_desc 所代表的红黑树
			中查找，如果找到就返回，否则返回空
*/
	struct rb_node *n = proc->refs_by_desc.rb_node;
	struct binder_ref *ref;

	while (n)
	{
		ref = rb_entry(n, struct binder_ref, rb_node_desc);

		if (desc < ref->desc)
			n = n->rb_left;
		else if (desc > ref->desc)
			n = n->rb_right;
		else
			return ref;
	}
	return NULL;
}

static struct binder_ref *binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数实现的功能是根据node 查找ref，首先说明一下ref 存在于proc 的地方，根据
			代码中可看到，ref  在proc 结构中存在于两个红黑树中，同时存在于两个树中，
			分别为:
				第1  个就是refs_by_node 红黑树中
				第2  个就是refs_by_desc  红黑树中
			
			查找的原理是根据传入的node 在第1  个(refs_by_node) 红黑树中查找，分两种情况，
			A、找到了
				直接返回找到的ref
			B、没找到
				则新分配一个ref  的内存空间，将传入的参数node 赋值给新分配的ref 的域成员，
				然后将新的ref  插入到第1  个红黑树中。
				再遍历第2  个红黑树中的所有成员，然后为新分配的ref 计算一个目标值，即
				desc  值，然后再将新的ref  插入到第2  个红黑树中
			
*/
	struct rb_node *n;
	struct rb_node **p = &proc->refs_by_node.rb_node;
	struct rb_node *parent = NULL;
	struct binder_ref *ref, *new_ref;

	while (*p) 
	{
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_node);

		if (node < ref->node)
			p = &(*p)->rb_left;
		else if (node > ref->node)
			p = &(*p)->rb_right;
		else
			return ref;
	}
	
	new_ref = kzalloc(sizeof(*ref), GFP_KERNEL);
	if (new_ref == NULL)
		return NULL;
	
	binder_stats_created(BINDER_STAT_REF);
	new_ref->debug_id = ++binder_last_id;
	new_ref->proc = proc;
	new_ref->node = node;
	rb_link_node(&new_ref->rb_node_node, parent, p);
	rb_insert_color(&new_ref->rb_node_node, &proc->refs_by_node);

	new_ref->desc = (node == binder_context_mgr_node) ? 0 : 1;
	
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) 
	{
		ref = rb_entry(n, struct binder_ref, rb_node_desc);
		if (ref->desc > new_ref->desc)
			break;
		new_ref->desc = ref->desc + 1;
	}

	p = &proc->refs_by_desc.rb_node;
	while (*p)
	{
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_desc);

		if (new_ref->desc < ref->desc)
			p = &(*p)->rb_left;
		else if (new_ref->desc > ref->desc)
			p = &(*p)->rb_right;
		else
			BUG();
	}
	
	rb_link_node(&new_ref->rb_node_desc, parent, p);
	rb_insert_color(&new_ref->rb_node_desc, &proc->refs_by_desc);
	if (node) 
	{
		hlist_add_head(&new_ref->node_entry, &node->refs);

		binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d new ref %d desc %d for " "node %d\n", proc->pid, new_ref->debug_id, new_ref->desc, node->debug_id);
	} 
	else 
	{
		binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d new ref %d desc %d for " "dead node\n", proc->pid, new_ref->debug_id, new_ref->desc);
	}
	return new_ref;
}

static void binder_delete_ref(struct binder_ref *ref)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	binder_debug(BINDER_DEBUG_INTERNAL_REFS,"binder: %d delete ref %d desc %d for ""node %d\n", ref->proc->pid, ref->debug_id,ref->desc, ref->node->debug_id);

	rb_erase(&ref->rb_node_desc, &ref->proc->refs_by_desc);
	rb_erase(&ref->rb_node_node, &ref->proc->refs_by_node);
	
	if (ref->strong)
		binder_dec_node(ref->node, 1, 1);
	
	hlist_del(&ref->node_entry);
	binder_dec_node(ref->node, 0, 1);
	
	if (ref->death) 
	{
		binder_debug(BINDER_DEBUG_DEAD_BINDER,"binder: %d delete ref %d desc %d ""has death notification\n", ref->proc->pid,ref->debug_id, ref->desc);
		list_del(&ref->death->work.entry);
		kfree(ref->death);
		binder_stats_deleted(BINDER_STAT_DEATH);
	}
	
	kfree(ref);
	binder_stats_deleted(BINDER_STAT_REF);
}

static int binder_inc_ref(struct binder_ref *ref, int strong, struct list_head *target_list)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	int ret;
	if (strong) 
	{
		if (ref->strong == 0) 
		{
			ret = binder_inc_node(ref->node, 1, 1, target_list);
			if (ret)
				return ret;
		}
		ref->strong++;
	} 
	else 
	{
		if (ref->weak == 0) 
		{
			ret = binder_inc_node(ref->node, 0, 1, target_list);
			if (ret)
				return ret;
		}
		ref->weak++;
	}
	return 0;
}


static int binder_dec_ref(struct binder_ref *ref, int strong)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (strong)
	{
		if (ref->strong == 0) 
		{
			binder_user_error("binder: %d invalid dec strong, ""ref %d desc %d s %d w %d\n",ref->proc->pid, ref->debug_id,ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->strong--;
		if (ref->strong == 0) 
		{
			int ret;
			ret = binder_dec_node(ref->node, strong, 1);
			if (ret)
				return ret;
		}
	}
	else 
	{
		if (ref->weak == 0) 
		{
			binder_user_error("binder: %d invalid dec weak, ""ref %d desc %d s %d w %d\n", ref->proc->pid, ref->debug_id,ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->weak--;
	}
	
	if (ref->strong == 0 && ref->weak == 0)
		binder_delete_ref(ref);
	
	return 0;
}

static void binder_pop_transaction(struct binder_thread *target_thread, struct binder_transaction *t)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (target_thread) 
	{
		BUG_ON(target_thread->transaction_stack != t);
		BUG_ON(target_thread->transaction_stack->from != target_thread);
		target_thread->transaction_stack = target_thread->transaction_stack->from_parent;
		t->from = NULL;
	}
	
	t->need_reply = 0;
	
	if (t->buffer)
		t->buffer->transaction = NULL;
	
	kfree(t);
	binder_stats_deleted(BINDER_STAT_TRANSACTION);
}

static void binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_thread *target_thread;
	BUG_ON(t->flags & TF_ONE_WAY);
	
	while (1) 
	{
		target_thread = t->from;
		
		if (target_thread) 
		{
			if (target_thread->return_error != BR_OK &&target_thread->return_error2 == BR_OK)
			{
				target_thread->return_error2 = target_thread->return_error;
				target_thread->return_error = BR_OK;
			}
			
			if (target_thread->return_error == BR_OK) 
			{
				binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,"binder: send failed reply for ""transaction %d to %d:%d\n",t->debug_id, target_thread->proc->pid,target_thread->pid);

				binder_pop_transaction(target_thread, t);
				target_thread->return_error = error_code;
				wake_up_interruptible(&target_thread->wait);
			}
			else 
			{
				printk(KERN_ERR "binder: reply failed, target ""thread, %d:%d, has error code %d ""already\n", target_thread->proc->pid,target_thread->pid,target_thread->return_error);
			}
			return;
		}
		else
		{
			struct binder_transaction *next = t->from_parent;

			binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,"binder: send failed reply ""for transaction %d, target dead\n",t->debug_id);

			binder_pop_transaction(target_thread, t);
			if (next == NULL)
			{
				binder_debug(BINDER_DEBUG_DEAD_BINDER,"binder: reply failed,"" no target thread at root\n");
				return;
			}
			
			t = next;
			binder_debug(BINDER_DEBUG_DEAD_BINDER,"binder: reply failed, no target ""thread -- retry %d\n", t->debug_id);
		}
	}
}

static void binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer, size_t *failed_at)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	size_t *offp, *off_end;
	int debug_id = buffer->debug_id;

	binder_debug(BINDER_DEBUG_TRANSACTION,"binder: %d buffer release %d, size %zd-%zd, failed at %p\n",proc->pid, buffer->debug_id,buffer->data_size, buffer->offsets_size, failed_at);

	if (buffer->target_node)
		binder_dec_node(buffer->target_node, 1, 0);

	offp = (size_t *)(buffer->data + ALIGN(buffer->data_size, sizeof(void *)));
	
	if (failed_at)
		off_end = failed_at;
	else
		off_end = (void *)offp + buffer->offsets_size;
	
	for (; offp < off_end; offp++) 
	{
		struct flat_binder_object *fp;
		
		if (*offp > buffer->data_size - sizeof(*fp) ||buffer->data_size < sizeof(*fp) ||!IS_ALIGNED(*offp, sizeof(void *))) 
		{
			printk(KERN_ERR "binder: transaction release %d bad""offset %zd, size %zd\n", debug_id,*offp, buffer->data_size);
			continue;
		}
		
		fp = (struct flat_binder_object *)(buffer->data + *offp);
		
		switch (fp->type)
		{
			case BINDER_TYPE_BINDER:
			case BINDER_TYPE_WEAK_BINDER: 
				{
					struct binder_node *node = binder_get_node(proc, fp->binder);
					
					if (node == NULL) 
					{
						printk(KERN_ERR "binder: transaction release %d"" bad node %p\n", debug_id, fp->binder);
						break;
					}
					binder_debug(BINDER_DEBUG_TRANSACTION,"        node %d u%p\n",node->debug_id, node->ptr);
					binder_dec_node(node, fp->type == BINDER_TYPE_BINDER, 0);
				} 
				break;
				
			case BINDER_TYPE_HANDLE:
			case BINDER_TYPE_WEAK_HANDLE: 
				{
					struct binder_ref *ref = binder_get_ref(proc, fp->handle);
					if (ref == NULL) 
					{
						printk(KERN_ERR "binder: transaction release %d"" bad handle %ld\n", debug_id,fp->handle);
						break;
					}
					binder_debug(BINDER_DEBUG_TRANSACTION,"        ref %d desc %d (node %d)\n",ref->debug_id, ref->desc, ref->node->debug_id);
					binder_dec_ref(ref, fp->type == BINDER_TYPE_HANDLE);
				} 
				break;

			case BINDER_TYPE_FD:
				binder_debug(BINDER_DEBUG_TRANSACTION,"        fd %ld\n", fp->handle);
				
				if (failed_at)
					task_close_fd(proc, fp->handle);
				break;

			default:
				printk(KERN_ERR "binder: transaction release %d bad ""object type %lx\n", debug_id, fp->type);
				break;
		}
	}
}

static void binder_transaction(struct binder_proc *proc, struct binder_thread *thread, struct binder_transaction_data *tr, int reply)
{
/*
	参数:
		1、proc 		: 传入由open 函数分配的内存数据结构
		2、thread 		: 传入thread 数据结构
		3、tr 			: 传入binder_transaction_data 数据结构
		4、reply 		: 传入是否为应答，0 非应答
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_transaction *t;
	struct binder_work *tcomplete;
	size_t *offp, *off_end;
	struct binder_proc *target_proc;
	struct binder_thread *target_thread = NULL;
	struct binder_node *target_node = NULL;
	struct list_head *target_list;
	wait_queue_head_t *target_wait;
	struct binder_transaction *in_reply_to = NULL;
	struct binder_transaction_log_entry *e;
	uint32_t return_error;

	e = binder_transaction_log_add(&binder_transaction_log);
	e->call_type = reply ? 2 : !!(tr->flags & TF_ONE_WAY);
	e->from_proc = proc->pid; /* 取出proc 对应的线程组长的pid */
	e->from_thread = thread->pid; /* 取出发送线程的pid */
	e->target_handle = tr->target.handle; /* 取出远端binder 对象的索引值*/
	e->data_size = tr->data_size;
	e->offsets_size = tr->offsets_size;

	if (reply) /* 为应答*/
	{
		in_reply_to = thread->transaction_stack;
		if (in_reply_to == NULL) 
		{
			binder_user_error("binder: %d:%d got reply transaction ""with no transaction stack\n",proc->pid, thread->pid);
			return_error = BR_FAILED_REPLY;
			goto err_empty_call_stack;
		}
		binder_set_nice(in_reply_to->saved_priority);
		
		if (in_reply_to->to_thread != thread)
		{
			binder_user_error("binder: %d:%d got reply transaction ""with bad transaction stack,"" transaction %d has target %d:%d\n",proc->pid, thread->pid, in_reply_to->debug_id,in_reply_to->to_proc ?in_reply_to->to_proc->pid : 0,in_reply_to->to_thread ?in_reply_to->to_thread->pid : 0);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			goto err_bad_call_stack;
		}
		
		thread->transaction_stack = in_reply_to->to_parent;
		target_thread = in_reply_to->from;
		if (target_thread == NULL)
		{
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		
		if (target_thread->transaction_stack != in_reply_to)
		{
			binder_user_error("binder: %d:%d got reply transaction ""with bad target transaction stack %d, ""expected %d\n",proc->pid, thread->pid,target_thread->transaction_stack ?target_thread->transaction_stack->debug_id : 0,in_reply_to->debug_id);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			target_thread = NULL;
			goto err_dead_binder;
		}
		target_proc = target_thread->proc;
	}
	else /* 为非应答*/
	{
		if (tr->target.handle) /* 如果此值不为0，则表示为远端的索引，所以要根据此索引找到其ref 结构*/
		{
			struct binder_ref *ref;
			ref = binder_get_ref(proc, tr->target.handle);
			if (ref == NULL) 
			{
				binder_user_error("binder: %d:%d got ""transaction to invalid handle\n",proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
				goto err_invalid_target_handle;
			}
			target_node = ref->node;
		} 
		else /* 将数据写给server 的*/
		{
			target_node = binder_context_mgr_node;
			if (target_node == NULL) 
			{
				return_error = BR_DEAD_REPLY;
				goto err_no_context_mgr_node;
			}
		}
		
		e->to_node = target_node->debug_id;
		target_proc = target_node->proc;
		
		if (target_proc == NULL) 
		{
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}

		/*
			如果不是单向传递，并且本进程收到的需要处理的堆栈不为空，则根据
			收到的信息来获取对方的信息
		*/
		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) 
		{
			struct binder_transaction *tmp;
			tmp = thread->transaction_stack;
			if (tmp->to_thread != thread) /* 如果堆栈中的信息不是发送给本线程的，一定是出错了*/
			{
				binder_user_error("binder: %d:%d got new ""transaction with bad transaction stack"", transaction %d has target %d:%d\n",proc->pid, thread->pid, tmp->debug_id,tmp->to_proc ? tmp->to_proc->pid : 0,tmp->to_thread ?tmp->to_thread->pid : 0);
				return_error = BR_FAILED_REPLY;
				goto err_bad_call_stack;
			}
			
			while (tmp) 
			{
				if (tmp->from && tmp->from->proc == target_proc)
					target_thread = tmp->from;/* 取出堆栈中某个信息来自哪个线程的*/
				
				tmp = tmp->from_parent;
			}
		}
	}
	
	if (target_thread) /* 找到目标线程*/
	{
		e->to_thread = target_thread->pid;
		target_list = &target_thread->todo;
		target_wait = &target_thread->wait; 
	} 
	else /* 没找到目标线程，则把proc 中保存的目标线程组长作为目标，即进程*/
	{
		target_list = &target_proc->todo;
		target_wait = &target_proc->wait;
	}
	e->to_proc = target_proc->pid;

	/* TODO: reuse incoming transaction for reply */
	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (t == NULL)
	{
		return_error = BR_FAILED_REPLY;
		goto err_alloc_t_failed;
	}
	binder_stats_created(BINDER_STAT_TRANSACTION);

	tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
	if (tcomplete == NULL) 
	{
		return_error = BR_FAILED_REPLY;
		goto err_alloc_tcomplete_failed;
	}
	binder_stats_created(BINDER_STAT_TRANSACTION_COMPLETE);

	t->debug_id = ++binder_last_id;
	e->debug_id = t->debug_id;

	if (reply)
		binder_debug(BINDER_DEBUG_TRANSACTION,"binder: %d:%d BC_REPLY %d -> %d:%d, ""data %p-%p size %zd-%zd\n",proc->pid, thread->pid, t->debug_id,target_proc->pid, target_thread->pid,tr->data.ptr.buffer, tr->data.ptr.offsets,tr->data_size, tr->offsets_size);
	else
		binder_debug(BINDER_DEBUG_TRANSACTION,"binder: %d:%d BC_TRANSACTION %d -> ""%d - node %d, data %p-%p size %zd-%zd\n",proc->pid, thread->pid, t->debug_id,target_proc->pid, target_node->debug_id,tr->data.ptr.buffer, tr->data.ptr.offsets,tr->data_size, tr->offsets_size);

	if (!reply && !(tr->flags & TF_ONE_WAY))
		t->from = thread;
	else
		t->from = NULL;
	
	t->sender_euid = proc->tsk->cred->euid;
	t->to_proc = target_proc;
	t->to_thread = target_thread;
	t->code = tr->code;
	t->flags = tr->flags;
	t->priority = task_nice(current);
	/* 在目的进程或线程的proc 数据结构来进行内存分配*/
	t->buffer = binder_alloc_buf(target_proc, tr->data_size,tr->offsets_size, !reply && (t->flags & TF_ONE_WAY)); /* 见函数内部，实现分配buffer ，并插入到proc 的allocated_buffers 红黑树中*/
	
	if (t->buffer == NULL) 
	{
		return_error = BR_FAILED_REPLY;
		goto err_binder_alloc_buf_failed;
	}
	t->buffer->allow_user_free = 0;
	t->buffer->debug_id = t->debug_id;
	t->buffer->transaction = t;
	t->buffer->target_node = target_node;

	/*
		-------------------------------------------------------------------------------
		| XXXXX data XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | #### offset data ####  |
		-------------------------------------------------------------------------------
		|					     								     |						   |
		addr1				     								     addr2					   addr3

		binder_buffer -> data_size		= addr2 - addr1
		binder_buffer -> offsets_size	= addr3 - addr2
		binder_buffer -> data			= addr1

		由上述的分析可知代码中的如下值:
		tr->offsets_size 		= addr3 - addr2
		tr->data.ptr.offsets	= addr2
		tr->data_size 			= addr2 - addr1
		t->buffer->data 		= addr1
	*/
	
	if (target_node)
		binder_inc_node(target_node, 1, 0, NULL);

	offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));

	/* 将用户空间的数据拷贝过来*/
	if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) 
	{
		binder_user_error("binder: %d:%d got transaction with invalid ""data ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}

	/* 将用户空间的offset 数据拷贝过来*/
	if (copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size)) 
	{
		binder_user_error("binder: %d:%d got transaction with invalid ""offsets ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	
	if (!IS_ALIGNED(tr->offsets_size, sizeof(size_t)))
	{
		binder_user_error("binder: %d:%d got transaction with ""invalid offsets size, %zd\n",proc->pid, thread->pid, tr->offsets_size);
		return_error = BR_FAILED_REPLY;
		goto err_bad_offset;
	}

	/* 分析offset 数据*/
	off_end = (void *)offp + tr->offsets_size;
	for (; offp < off_end; offp++) 
	{
		struct flat_binder_object *fp;
		
		if (*offp > t->buffer->data_size - sizeof(*fp) ||t->buffer->data_size < sizeof(*fp) ||!IS_ALIGNED(*offp, sizeof(void *))) 
		{
			binder_user_error("binder: %d:%d got transaction with ""invalid offset, %zd\n",proc->pid, thread->pid, *offp);
			return_error = BR_FAILED_REPLY;
			goto err_bad_offset;
		}
		
		fp = (struct flat_binder_object *)(t->buffer->data + *offp);
		
		switch (fp->type) 
		{
			/* 本地对象*/
			case BINDER_TYPE_BINDER:
			case BINDER_TYPE_WEAK_BINDER: 
				{
					struct binder_ref *ref;

					/*
						先在本地的proc 结构中根据传入的信息来查找node 结构，如果找到就ok，如果
						没找到那就在本地proc 结构中分配一个node 结构，并对其进行相应的赋值
					*/
					struct binder_node *node = binder_get_node(proc, fp->binder);

					/* 获得到本地proc 中的节点*/
					if (node == NULL) 
					{
						node = binder_new_node(proc, fp->binder, fp->cookie);
						if (node == NULL)
						{
							return_error = BR_FAILED_REPLY;
							goto err_binder_new_node_failed;
						}
						node->min_priority = fp->flags & FLAT_BINDER_FLAG_PRIORITY_MASK;
						node->accept_fds = !!(fp->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);
					}
					
					if (fp->cookie != node->cookie)
					{
						binder_user_error("binder: %d:%d sending u%p ""node %d, cookie mismatch %p != %p\n",proc->pid, thread->pid,fp->binder, node->debug_id,fp->cookie, node->cookie);
						goto err_binder_get_ref_for_node_failed;
					}

					/*
						程序执行到此处时本地的node  结构一定已经存在了，所以需要根据这个
						node 的结构来在目的proc 的结构中找到一个指向此node 的ref，如果目的proc
						结构中没有这样的ref 那么就在目的proc 中分配一个ref，并将ref 指向此node
					*/

					/* 获得目的proc 中的ref  (  注意是利用本地的node 获取目的proc 的ref ，见函数binder_get_ref_for_node 说明会在目的端生成ref 的引用，但ref 的node 为本地的)*/
					ref = binder_get_ref_for_node(target_proc, node);
					if (ref == NULL) 
					{
						return_error = BR_FAILED_REPLY;
						goto err_binder_get_ref_for_node_failed;
					}
					
					if (fp->type == BINDER_TYPE_BINDER)
						fp->type = BINDER_TYPE_HANDLE;
					else
						fp->type = BINDER_TYPE_WEAK_HANDLE;
					
					fp->handle = ref->desc;
					binder_inc_ref(ref, fp->type == BINDER_TYPE_HANDLE,&thread->todo);

					binder_debug(BINDER_DEBUG_TRANSACTION,"        node %d u%p -> ref %d desc %d\n",node->debug_id, node->ptr, ref->debug_id,ref->desc);
				}
				break;

			/* 远程对象的引用*/
			case BINDER_TYPE_HANDLE:
			case BINDER_TYPE_WEAK_HANDLE:
				{
					struct binder_ref *ref = binder_get_ref(proc, fp->handle);
					
					if (ref == NULL)
					{
						binder_user_error("binder: %d:%d got ""transaction with invalid ""handle, %ld\n", proc->pid,thread->pid, fp->handle);
						return_error = BR_FAILED_REPLY;
						goto err_binder_get_ref_failed;
					}
					
					if (ref->node->proc == target_proc) 
					{
						if (fp->type == BINDER_TYPE_HANDLE)
							fp->type = BINDER_TYPE_BINDER;
						else
							fp->type = BINDER_TYPE_WEAK_BINDER;
						
						fp->binder = ref->node->ptr;
						fp->cookie = ref->node->cookie;
						binder_inc_node(ref->node, fp->type == BINDER_TYPE_BINDER, 0, NULL);
						binder_debug(BINDER_DEBUG_TRANSACTION,"        ref %d desc %d -> node %d u%p\n",ref->debug_id, ref->desc, ref->node->debug_id,ref->node->ptr);
					} 
					else 
					{
						struct binder_ref *new_ref;
						new_ref = binder_get_ref_for_node(target_proc, ref->node);
						
						if (new_ref == NULL) 
						{
							return_error = BR_FAILED_REPLY;
							goto err_binder_get_ref_for_node_failed;
						}
						
						fp->handle = new_ref->desc;
						binder_inc_ref(new_ref, fp->type == BINDER_TYPE_HANDLE, NULL);
						binder_debug(BINDER_DEBUG_TRANSACTION,"        ref %d desc %d -> ref %d desc %d (node %d)\n",ref->debug_id, ref->desc, new_ref->debug_id,new_ref->desc, ref->node->debug_id);
					}
				}
				break;

			case BINDER_TYPE_FD: 
				{
					int target_fd;
					struct file *file;

					if (reply) 
					{
						if (!(in_reply_to->flags & TF_ACCEPT_FDS))
						{
							binder_user_error("binder: %d:%d got reply with fd, %ld, but target does not allow fds\n",proc->pid, thread->pid, fp->handle);
							return_error = BR_FAILED_REPLY;
							goto err_fd_not_allowed;
						}
					} 
					else if (!target_node->accept_fds) 
					{
						binder_user_error("binder: %d:%d got transaction with fd, %ld, but target does not allow fds\n",proc->pid, thread->pid, fp->handle);
						return_error = BR_FAILED_REPLY;
						goto err_fd_not_allowed;
					}

					file = fget(fp->handle);
					if (file == NULL) 
					{
						binder_user_error("binder: %d:%d got transaction with invalid fd, %ld\n",proc->pid, thread->pid, fp->handle);
						return_error = BR_FAILED_REPLY;
						goto err_fget_failed;
					}
					
					target_fd = task_get_unused_fd_flags(target_proc, O_CLOEXEC);
					if (target_fd < 0) 
					{
						fput(file);
						return_error = BR_FAILED_REPLY;
						goto err_get_unused_fd_failed;
					}
					
					task_fd_install(target_proc, target_fd, file);
					binder_debug(BINDER_DEBUG_TRANSACTION,"        fd %ld -> %d\n", fp->handle, target_fd);
					
					/* TODO: fput? */
					fp->handle = target_fd;
				}
				break;

			default:
				binder_user_error("binder: %d:%d got transactio""n with invalid object type, %lx\n",proc->pid, thread->pid, fp->type);
				return_error = BR_FAILED_REPLY;
				goto err_bad_object_type;
		}
	}
	
	if (reply) 
	{
		BUG_ON(t->buffer->async_transaction != 0);
		binder_pop_transaction(target_thread, in_reply_to);
	}
	else if (!(t->flags & TF_ONE_WAY)) 
	{
		BUG_ON(t->buffer->async_transaction != 0);
		t->need_reply = 1;
		t->from_parent = thread->transaction_stack;
		thread->transaction_stack = t;
	} 
	else 
	{
		BUG_ON(target_node == NULL);
		BUG_ON(t->buffer->async_transaction != 1);
		if (target_node->has_async_transaction) 
		{
			target_list = &target_node->async_todo;
			target_wait = NULL;
		} 
		else
			target_node->has_async_transaction = 1;
	}
	
	t->work.type = BINDER_WORK_TRANSACTION;
	list_add_tail(&t->work.entry, target_list);
	tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
	list_add_tail(&tcomplete->entry, &thread->todo);

	/* 唤醒目标线程或进程*/
	if (target_wait)
		wake_up_interruptible(target_wait);
	
	return;

err_get_unused_fd_failed:
err_fget_failed:
err_fd_not_allowed:
err_binder_get_ref_for_node_failed:
err_binder_get_ref_failed:
err_binder_new_node_failed:
err_bad_object_type:
err_bad_offset:
err_copy_data_failed:
	
	binder_transaction_buffer_release(target_proc, t->buffer, offp);
	t->buffer->transaction = NULL;
	binder_free_buf(target_proc, t->buffer);


err_binder_alloc_buf_failed:
	
	kfree(tcomplete);
	binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);

	
err_alloc_tcomplete_failed:
	
	kfree(t);
	binder_stats_deleted(BINDER_STAT_TRANSACTION);

	
err_alloc_t_failed:
err_bad_call_stack:
err_empty_call_stack:
err_dead_binder:
err_invalid_target_handle:
err_no_context_mgr_node:
	
	binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,"binder: %d:%d transaction failed %d, size %zd-%zd\n",proc->pid, thread->pid, return_error,tr->data_size, tr->offsets_size);

	{
		struct binder_transaction_log_entry *fe;
		fe = binder_transaction_log_add(&binder_transaction_log_failed);
		*fe = *e;
	}

	BUG_ON(thread->return_error != BR_OK);
	if (in_reply_to)
	{
		thread->return_error = BR_TRANSACTION_COMPLETE;
		binder_send_failed_reply(in_reply_to, return_error);
	} 
	else
		thread->return_error = return_error;
}

int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread, void __user *buffer, int size, signed long *consumed)
{
/*
	参数:
		1、proc 		: 传入由open 函数分配的内存数据结构，保存在文件数据结构的私有域中，即 filp->private_data
		2、thread 		: 传入thread 数据结构
		3、buffer 		: 传入待写出的数据buffer，为用户空间的地址，即用户空间要通过binder 驱动写数据时的待写出的数据内容
		4、size 			: 传入待写出数据buffer 的长度
		5、consumed 	: 传入时为从buffer 的什么地方开始为有效的数据，返回时为从buffer 的起始地址到已经写完的数据地址之间的长度
		
	返回:
		1、
		
	说明:
		1、
*/
	uint32_t cmd;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

/*
	传入数据buffer 中的数据格式:
		while(ptr < end && thread->return_error == BR_OK)
		{
			cmd : 4 个字节

			后续的数据根据cmd 的不同而进行定义，见代码
		}
*/

	while (ptr < end && thread->return_error == BR_OK) 
	{

		/* ===1====> cmd : 4 个字节	*/
		if (get_user(cmd, (uint32_t __user *)ptr)) /* 从用户空间中的buffer 中首先读取一个32 位的数据，此值为相应的命令*/
			return -EFAULT;

		ptr += sizeof(uint32_t);
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) 
		{
			binder_stats.bc[_IOC_NR(cmd)]++;
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}

		/*
			在这些命令中，最常用的是BC_TRANSACTION/BC_REPLY命令对，Binder数据通过这对命令发送给接收方。这
			对命令所承载的数 据包由结构体struct binder_transaction_data定义。Binder交互有同步和异步之分，利
			用binder_transaction_data中 flag域区分。如果flag域的TF_ONE_WAY位为1则为异步交互，即Client端发送完请求交互
			即结束， Server端不再返回BC_REPLY数据包；否则Server会返回BC_REPLY数据包，Client端必须等待接收完该
			数据包方才完成一次交互。
		*/
		
		switch (cmd) 
		{
			case BC_INCREFS:
			case BC_ACQUIRE:
			case BC_RELEASE:
			case BC_DECREFS: 
				{
					/*
						含义:
							这组命令增加或减少binder的引用计数，用以实现强指针或弱指针的功能。
						参数:
							32位binder引用号
					*/
					uint32_t target;
					struct binder_ref *ref;
					const char *debug_string;

					/* ===2====> target : 4 个字节	*/
					if (get_user(target, (uint32_t __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(uint32_t);

					/* 
						因为是写数据函数，所以要将数据写入到哪个binder 对象( 相当于哪个进程或线程) 就是通过
						远程的索引来确定的。因此先通过target 即远程索引找到ref 数据结构
					*/
					if (target == 0 && binder_context_mgr_node && (cmd == BC_INCREFS || cmd == BC_ACQUIRE))
					{
						ref = binder_get_ref_for_node(proc, binder_context_mgr_node);/* 见函数内部*/
						if (ref->desc != target) 
						{
							binder_user_error("binder: %d:""%d tried to acquire ""reference to desc 0, ""got %d instead\n",proc->pid, thread->pid,ref->desc);
						}
					} 
					else
						ref = binder_get_ref(proc, target);/* 见函数内部*/
					
					if (ref == NULL) 
					{
						binder_user_error("binder: %d:%d refcou""nt change on invalid ref %d\n",proc->pid, thread->pid, target);
						break;
					}

					/* 程序执行到此处一定是找到了一个binder_ref 数据结构*/
					
					switch (cmd) 
					{
						case BC_INCREFS:
							debug_string = "IncRefs";
							binder_inc_ref(ref, 0, NULL);
							break;
						
						case BC_ACQUIRE:
							debug_string = "Acquire";
							binder_inc_ref(ref, 1, NULL);
							break;
							
						case BC_RELEASE:
							debug_string = "Release";
							binder_dec_ref(ref, 1);
							break;
						
						case BC_DECREFS:
						default:
							debug_string = "DecRefs";
							binder_dec_ref(ref, 0);
							break;
					}
					binder_debug(BINDER_DEBUG_USER_REFS,"binder: %d:%d %s ref %d desc %d s %d w %d for node %d\n",proc->pid, thread->pid, debug_string, ref->debug_id,ref->desc, ref->strong, ref->weak, ref->node->debug_id);
					break;
				}
			
			case BC_INCREFS_DONE:
			case BC_ACQUIRE_DONE: 
				{
					/*
						含义:
							第一次增加binder实体应用计数时，驱动向binder实体所在的进程发送BR_INCREFS, BR_ACQUIRE消息；binder
							实体所在的进程处理完毕回馈BR_INCREFS_DONE, BR_ACQUIRE_DONE
						参数:
							void * ptr;  		binder实体在用户空间中的指针
							void* cookie; 		与该实体相关的附加数据
					*/
					void __user *node_ptr;
					void *cookie;
					struct binder_node *node;

					/* ===2====> node_ptr : 4 个字节	*/
					if (get_user(node_ptr, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);

					/* ===3====> cookie : 4 个字节	*/
					if (get_user(cookie, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);
					node = binder_get_node(proc, node_ptr); /* 见函数内部*/
					
					if (node == NULL) 
					{
						binder_user_error("binder: %d:%d ""%s u%p no match\n",proc->pid, thread->pid,cmd == BC_INCREFS_DONE ?"BC_INCREFS_DONE" :"BC_ACQUIRE_DONE",node_ptr);
						break;
					}
					
					if (cookie != node->cookie) 
					{
						binder_user_error("binder: %d:%d %s u%p node %d"" cookie mismatch %p != %p\n",proc->pid, thread->pid,cmd == BC_INCREFS_DONE ?"BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",node_ptr, node->debug_id,cookie, node->cookie);
						break;
					}
					
					if (cmd == BC_ACQUIRE_DONE) 
					{
						if (node->pending_strong_ref == 0) 
						{
							binder_user_error("binder: %d:%d ""BC_ACQUIRE_DONE node %d has ""no pending acquire request\n",proc->pid, thread->pid,node->debug_id);
							break;
						}
						node->pending_strong_ref = 0;
					} 
					else 
					{
						if (node->pending_weak_ref == 0) 
						{
							binder_user_error("binder: %d:%d ""BC_INCREFS_DONE node %d has ""no pending increfs request\n",proc->pid, thread->pid,node->debug_id);
							break;
						}
						node->pending_weak_ref = 0;
					}
					
					binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
					binder_debug(BINDER_DEBUG_USER_REFS,"binder: %d:%d %s node %d ls %d lw %d\n",proc->pid, thread->pid,cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",node->debug_id, node->local_strong_refs, node->local_weak_refs);
					break;
				}
			case BC_ATTEMPT_ACQUIRE:
				printk(KERN_ERR "binder: BC_ATTEMPT_ACQUIRE not supported\n");
				return -EINVAL;
				
			case BC_ACQUIRE_RESULT:
				printk(KERN_ERR "binder: BC_ACQUIRE_RESULT not supported\n");
				return -EINVAL;

			case BC_FREE_BUFFER: 
				{
					/*
						含义:
							释放一块映射的内存。binder接收方通过mmap()映射一块较大的内存空间，binder驱动基于这片
							内存采用最佳匹配算法实现接收数据缓存的动态分配和释放，满足并发请求对接收缓存
							的需求。应用程序处理完这片数据后必须尽快使用该命令释放缓存区，否则会因为缓存
							区耗尽而无法接收新数据
						参数:
							指向需要释放的缓存区的指针；该指针位于收到的binder数据包中
					*/
					void __user *data_ptr;
					struct binder_buffer *buffer;

					/* ===2====> data_ptr : 4 个字节	*/
					if (get_user(data_ptr, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);

					buffer = binder_buffer_lookup(proc, data_ptr); /* 见函数内部*/
					if (buffer == NULL)
					{
						binder_user_error("binder: %d:%d ""BC_FREE_BUFFER u%p no match\n",proc->pid, thread->pid, data_ptr);
						break;
					}
					
					if (!buffer->allow_user_free) 
					{
						binder_user_error("binder: %d:%d ""BC_FREE_BUFFER u%p matched ""unreturned buffer\n",proc->pid, thread->pid, data_ptr);
						break;
					}
					
					binder_debug(BINDER_DEBUG_FREE_BUFFER,"binder: %d:%d BC_FREE_BUFFER u%p found buffer %d for %s transaction\n",proc->pid, thread->pid, data_ptr, buffer->debug_id,buffer->transaction ? "active" : "finished");

					if (buffer->transaction)
					{
						buffer->transaction->buffer = NULL;
						buffer->transaction = NULL;
					}
					
					if (buffer->async_transaction && buffer->target_node) 
					{
						BUG_ON(!buffer->target_node->has_async_transaction);
						
						if (list_empty(&buffer->target_node->async_todo))
							buffer->target_node->has_async_transaction = 0;
						else
							list_move_tail(buffer->target_node->async_todo.next, &thread->todo);
					}
					binder_transaction_buffer_release(proc, buffer, NULL);
					binder_free_buf(proc, buffer);
					break;
				}

			case BC_TRANSACTION:	/* 写入请求数据*/
			case BC_REPLY: /* 写入回复数据*/
				{
					struct binder_transaction_data tr;

					/* ===2====> data_ptr : sizeof(tr) 个字节	*/
					if (copy_from_user(&tr, ptr, sizeof(tr)))
						return -EFAULT;

					/*
						如果是transaction ，则待写入的数据开始的部分一定是一个binder_transaction_data 类型的数据结构
						，所以先取出这个数据结构，然后调用binder_transaction 函数执行，见函数binder_transaction 
					*/
					
					ptr += sizeof(tr);
					binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
					break;
				}

			case BC_REGISTER_LOOPER:
				/*
					含义:
						此命令同BINDER_SET_MAX_THREADS一道实现binder驱动对接收方线程池管理。BC_REGISTER_LOOPER通知驱动
						线程池中一个线程已经创建了；BC_ENTER_LOOPER通知驱动线程已经进入主循环，可以接收数据；
						BC_EXIT_LOOPER通知驱动线程退出主循环，不再接收数据
				*/
				binder_debug(BINDER_DEBUG_THREADS,"binder: %d:%d BC_REGISTER_LOOPER\n",proc->pid, thread->pid);
				
				if (thread->looper & BINDER_LOOPER_STATE_ENTERED) 
				{
					thread->looper |= BINDER_LOOPER_STATE_INVALID;
					binder_user_error("binder: %d:%d ERROR:"" BC_REGISTER_LOOPER called ""after BC_ENTER_LOOPER\n",proc->pid, thread->pid);
				}
				else if (proc->requested_threads == 0) 
				{
					thread->looper |= BINDER_LOOPER_STATE_INVALID;
					binder_user_error("binder: %d:%d ERROR:"" BC_REGISTER_LOOPER called ""without request\n",proc->pid, thread->pid);
				} 
				else 
				{
					proc->requested_threads--;
					proc->requested_threads_started++;
				}
				
				thread->looper |= BINDER_LOOPER_STATE_REGISTERED; /* 增加了sevice manager  线程的注册标记*/
				break;
				
			case BC_ENTER_LOOPER:
				/*
					含义:
						此命令同BINDER_SET_MAX_THREADS一道实现binder驱动对接收方线程池管理。BC_REGISTER_LOOPER通知驱动
						线程池中一个线程已经创建了；BC_ENTER_LOOPER通知驱动线程已经进入主循环，可以接收数据；
						BC_EXIT_LOOPER通知驱动线程退出主循环，不再接收数据
				*/
				binder_debug(BINDER_DEBUG_THREADS,"binder: %d:%d BC_ENTER_LOOPER\n",proc->pid, thread->pid);
				
				if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) 
				{
					thread->looper |= BINDER_LOOPER_STATE_INVALID;
					binder_user_error("binder: %d:%d ERROR:"" BC_ENTER_LOOPER called after ""BC_REGISTER_LOOPER\n",proc->pid, thread->pid);
				}
				thread->looper |= BINDER_LOOPER_STATE_ENTERED;
				break;
				
			case BC_EXIT_LOOPER:
				/*
					含义:
						此命令同BINDER_SET_MAX_THREADS一道实现binder驱动对接收方线程池管理。BC_REGISTER_LOOPER通知驱动
						线程池中一个线程已经创建了；BC_ENTER_LOOPER通知驱动线程已经进入主循环，可以接收数据；
						BC_EXIT_LOOPER通知驱动线程退出主循环，不再接收数据
				*/
				binder_debug(BINDER_DEBUG_THREADS,"binder: %d:%d BC_EXIT_LOOPER\n",proc->pid, thread->pid);
				thread->looper |= BINDER_LOOPER_STATE_EXITED;
				break;

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION: 
				{
					/*
						含义:
							获得binder引用的进程通过该命令要求驱动在binder实体销毁得到通知。虽说强指针可以确保
							只要有引用就不会销毁实体，但这毕竟是个跨进程的引用，谁也无法保证实体由于所在
							的server关闭binder驱动而异常退出而消失，引用者能做的是要求server在此刻给出通知
							
						参数:
							uint32* ptr; 		需要得到死亡通知的binder引用
							void** cookie; 	与死亡通知相关的信息，驱动会在发出死亡通知时返回给发出请求的进程。
					*/
					uint32_t target;
					void __user *cookie;
					struct binder_ref *ref;
					struct binder_ref_death *death;

					/* ===2====> target : 4 个字节	*/
					if (get_user(target, (uint32_t __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(uint32_t);

					/* ===3====> cookie : 4 个字节	*/
					if (get_user(cookie, (void __user * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);
					
					ref = binder_get_ref(proc, target);
					if (ref == NULL) 
					{
						binder_user_error("binder: %d:%d %s ""invalid ref %d\n",proc->pid, thread->pid,cmd == BC_REQUEST_DEATH_NOTIFICATION ?"BC_REQUEST_DEATH_NOTIFICATION" :"BC_CLEAR_DEATH_NOTIFICATION",target);
						break;
					}

					binder_debug(BINDER_DEBUG_DEATH_NOTIFICATION,"binder: %d:%d %s %p ref %d desc %d s %d w %d for node %d\n",proc->pid, thread->pid,cmd == BC_REQUEST_DEATH_NOTIFICATION ?"BC_REQUEST_DEATH_NOTIFICATION" :"BC_CLEAR_DEATH_NOTIFICATION",cookie, ref->debug_id, ref->desc,ref->strong, ref->weak, ref->node->debug_id);

					if (cmd == BC_REQUEST_DEATH_NOTIFICATION) 
					{
						if (ref->death)
						{
							binder_user_error("binder: %d:%""d BC_REQUEST_DEATH_NOTI""FICATION death notific""ation already set\n",proc->pid, thread->pid);
							break;
						}
						death = kzalloc(sizeof(*death), GFP_KERNEL);
						if (death == NULL) 
						{
							thread->return_error = BR_ERROR;
							binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,"binder: %d:%d ""BC_REQUEST_DEATH_NOTIFICATION failed\n",proc->pid, thread->pid);
							break;
						}
						
						binder_stats_created(BINDER_STAT_DEATH);
						INIT_LIST_HEAD(&death->work.entry);
						
						death->cookie = cookie;
						ref->death = death;
						
						if (ref->node->proc == NULL) 
						{
							ref->death->work.type = BINDER_WORK_DEAD_BINDER;
							if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) 
							{
								list_add_tail(&ref->death->work.entry, &thread->todo);
							} 
							else
							{
								list_add_tail(&ref->death->work.entry, &proc->todo);
								wake_up_interruptible(&proc->wait);
							}
						}
					}
					else 
					{
						if (ref->death == NULL) 
						{
							binder_user_error("binder: %d:%""d BC_CLEAR_DEATH_NOTIFI""CATION death notificat""ion not active\n",proc->pid, thread->pid);
							break;
						}
						
						death = ref->death;
						if (death->cookie != cookie) 
						{
							binder_user_error("binder: %d:%""d BC_CLEAR_DEATH_NOTIFI""CATION death notificat""ion cookie mismatch ""%p != %p\n",proc->pid, thread->pid,death->cookie, cookie);
							break;
						}
						
						ref->death = NULL;
						
						if (list_empty(&death->work.entry)) 
						{
							death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
							if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED))
							{
								list_add_tail(&death->work.entry, &thread->todo);
							} 
							else 
							{
								list_add_tail(&death->work.entry, &proc->todo);
								wake_up_interruptible(&proc->wait);
							}
						} 
						else 
						{
							BUG_ON(death->work.type != BINDER_WORK_DEAD_BINDER);
							death->work.type = BINDER_WORK_DEAD_BINDER_AND_CLEAR;
						}
					}
				} break;
			
			case BC_DEAD_BINDER_DONE: 
				{
					/*
						含义:
							收到实体死亡通知书的进程在删除应用后用本命令告知驱动
							
						参数:
							void** cookie; 
					*/
					struct binder_work *w;
					void __user *cookie;
					struct binder_ref_death *death = NULL;

					/* ===2====> cookie : 4 个字节	*/
					if (get_user(cookie, (void __user * __user *)ptr))
						return -EFAULT;

					ptr += sizeof(void *);
					
					list_for_each_entry(w, &proc->delivered_death, entry) 
					{
						struct binder_ref_death *tmp_death = container_of(w, struct binder_ref_death, work);
						
						if (tmp_death->cookie == cookie) 
						{
							death = tmp_death;
							break;
						}
					}
					
					binder_debug(BINDER_DEBUG_DEAD_BINDER,"binder: %d:%d BC_DEAD_BINDER_DONE %p found %p\n",proc->pid, thread->pid, cookie, death);
					
					if (death == NULL) 
					{
						binder_user_error("binder: %d:%d BC_DEAD""_BINDER_DONE %p not found\n",proc->pid, thread->pid, cookie);
						break;
					}

					list_del_init(&death->work.entry);
					
					if (death->work.type == BINDER_WORK_DEAD_BINDER_AND_CLEAR) 
					{
						death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
						if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) 
						{
							list_add_tail(&death->work.entry, &thread->todo);
						} 
						else
						{
							list_add_tail(&death->work.entry, &proc->todo);
							wake_up_interruptible(&proc->wait);
						}
					}
				} break;

			default:
				printk(KERN_ERR "binder: %d:%d unknown command %d\n",
				proc->pid, thread->pid, cmd);
				return -EINVAL;
		}
		
		*consumed = ptr - buffer;
	}
	return 0;
}

void binder_stat_br(struct binder_proc *proc, struct binder_thread *thread, uint32_t cmd)
{
	if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.br)) 
	{
		binder_stats.br[_IOC_NR(cmd)]++;
		proc->stats.br[_IOC_NR(cmd)]++;
		thread->stats.br[_IOC_NR(cmd)]++;
	}
}

static int binder_has_proc_work(struct binder_proc *proc, struct binder_thread *thread)
{
	return !list_empty(&proc->todo) || (thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

static int binder_has_thread_work(struct binder_thread *thread)
{
	return !list_empty(&thread->todo) || thread->return_error != BR_OK || (thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

static int binder_thread_read(struct binder_proc *proc, struct binder_thread *thread, void  __user *buffer, int size, signed long *consumed, int non_block)
{
/*
	参数:
		1、proc 		: 传入由open 函数分配的内存数据结构，保存在文件数据结构的私有域中，即 filp->private_data
		2、thread 		: 传入thread 数据结构
		3、buffer 		: 传入保存读取数据的内存空间，用于返回读出的数据内容
		4、size 			: 传入保存读取数据空间的大小
		5、consumed 	: 用于返回读取到的数据长度( 如果传入时此值为0  则先向buffer  中写入一个BR_NOOP  )
		6、non_block	: 是否阻塞
		
	返回:
		1、
		
	说明:
		1、
*/
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	int ret = 0;
	int wait_for_proc_work;

	if (*consumed == 0) /* 此值为0，则先向buffer  中写入BR_NOOP  */
	{
		if (put_user(BR_NOOP, (uint32_t __user *)ptr))
			return -EFAULT;
		
		ptr += sizeof(uint32_t);
	}

retry:
	wait_for_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo);

	if (thread->return_error != BR_OK && ptr < end) 
	{
		if (thread->return_error2 != BR_OK) 
		{
			if (put_user(thread->return_error2, (uint32_t __user *)ptr))
				return -EFAULT;
			
			ptr += sizeof(uint32_t);
			
			if (ptr == end)
				goto done;
			
			thread->return_error2 = BR_OK;
		}
		
		if (put_user(thread->return_error, (uint32_t __user *)ptr))
			return -EFAULT;
		
		ptr += sizeof(uint32_t);
		thread->return_error = BR_OK;
		goto done;
	}


	thread->looper |= BINDER_LOOPER_STATE_WAITING;
	
	if (wait_for_proc_work)
		proc->ready_threads++;
	
	mutex_unlock(&binder_lock);
	
	if (wait_for_proc_work) 
	{
		if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED |BINDER_LOOPER_STATE_ENTERED))) 
		{
			binder_user_error("binder: %d:%d ERROR: Thread waiting ""for process work before calling BC_REGISTER_""LOOPER or BC_ENTER_LOOPER (state %x)\n",proc->pid, thread->pid, thread->looper);

			wait_event_interruptible(binder_user_error_wait,binder_stop_on_user_error < 2);
		}
		binder_set_nice(proc->default_priority);
		
		if (non_block)
		{
			if (!binder_has_proc_work(proc, thread))
				ret = -EAGAIN;
		} 
		else
			ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
	} 
	else 
	{
		if (non_block) 
		{
			if (!binder_has_thread_work(thread))
				ret = -EAGAIN;
		} 
		else
			ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
	}
	mutex_lock(&binder_lock);
	
	if (wait_for_proc_work)
		proc->ready_threads--;
	
	thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

	if (ret)
		return ret;

	while (1) 
	{
		uint32_t cmd;
		struct binder_transaction_data tr;
		struct binder_work *w;
		struct binder_transaction *t = NULL;

		if (!list_empty(&thread->todo))
			w = list_first_entry(&thread->todo, struct binder_work, entry);
		else if (!list_empty(&proc->todo) && wait_for_proc_work)
			w = list_first_entry(&proc->todo, struct binder_work, entry);
		else 
		{
			if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
				goto retry;
			
			break;
		}

		if (end - ptr < sizeof(tr) + 4)
			break;

		switch (w->type) 
		{
			case BINDER_WORK_TRANSACTION: 
				{
					t = container_of(w, struct binder_transaction, work);
				} 
				break;
				
			case BINDER_WORK_TRANSACTION_COMPLETE: 
				{
					cmd = BR_TRANSACTION_COMPLETE;
					
					if (put_user(cmd, (uint32_t __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(uint32_t);

					binder_stat_br(proc, thread, cmd);
					binder_debug(BINDER_DEBUG_TRANSACTION_COMPLETE,"binder: %d:%d BR_TRANSACTION_COMPLETE\n",proc->pid, thread->pid);

					list_del(&w->entry);
					kfree(w);
					binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
				} 
				break;
				
			case BINDER_WORK_NODE: 
				{
					struct binder_node *node = container_of(w, struct binder_node, work);
					uint32_t cmd = BR_NOOP;
					const char *cmd_name;
					int strong = node->internal_strong_refs || node->local_strong_refs;
					int weak = !hlist_empty(&node->refs) || node->local_weak_refs || strong;
					
					if (weak && !node->has_weak_ref) 
					{
						cmd = BR_INCREFS;
						cmd_name = "BR_INCREFS";
						node->has_weak_ref = 1;
						node->pending_weak_ref = 1;
						node->local_weak_refs++;
					} 
					else if (strong && !node->has_strong_ref)
					{
						cmd = BR_ACQUIRE;
						cmd_name = "BR_ACQUIRE";
						node->has_strong_ref = 1;
						node->pending_strong_ref = 1;
						node->local_strong_refs++;
					} 
					else if (!strong && node->has_strong_ref) 
					{
						cmd = BR_RELEASE;
						cmd_name = "BR_RELEASE";
						node->has_strong_ref = 0;
					}
					else if (!weak && node->has_weak_ref) 
					{
						cmd = BR_DECREFS;
						cmd_name = "BR_DECREFS";
						node->has_weak_ref = 0;
					}
					
					if (cmd != BR_NOOP) 
					{
						if (put_user(cmd, (uint32_t __user *)ptr))
							return -EFAULT;
						
						ptr += sizeof(uint32_t);
						
						if (put_user(node->ptr, (void * __user *)ptr))
							return -EFAULT;
						
						ptr += sizeof(void *);
						if (put_user(node->cookie, (void * __user *)ptr))
							return -EFAULT;
						
						ptr += sizeof(void *);

						binder_stat_br(proc, thread, cmd);
						binder_debug(BINDER_DEBUG_USER_REFS,"binder: %d:%d %s %d u%p c%p\n",proc->pid, thread->pid, cmd_name, node->debug_id, node->ptr, node->cookie);
					} 
					else 
					{
						list_del_init(&w->entry);
						
						if (!weak && !strong)
						{
							binder_debug(BINDER_DEBUG_INTERNAL_REFS,"binder: %d:%d node %d u%p c%p deleted\n",proc->pid, thread->pid, node->debug_id,node->ptr, node->cookie);
							rb_erase(&node->rb_node, &proc->nodes);
							kfree(node);
							binder_stats_deleted(BINDER_STAT_NODE);
						}
						else 
						{
							binder_debug(BINDER_DEBUG_INTERNAL_REFS,"binder: %d:%d node %d u%p c%p state unchanged\n",proc->pid, thread->pid, node->debug_id, node->ptr,node->cookie);
						}
					}
				} 
				break;
				
			case BINDER_WORK_DEAD_BINDER:
			case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
			case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: 
				{
					struct binder_ref_death *death;
					uint32_t cmd;

					death = container_of(w, struct binder_ref_death, work);
					
					if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION)
						cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
					else
						cmd = BR_DEAD_BINDER;
					
					if (put_user(cmd, (uint32_t __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(uint32_t);
					
					if (put_user(death->cookie, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);
					
					binder_debug(BINDER_DEBUG_DEATH_NOTIFICATION,"binder: %d:%d %s %p\n",proc->pid, thread->pid,cmd == BR_DEAD_BINDER ?"BR_DEAD_BINDER" :"BR_CLEAR_DEATH_NOTIFICATION_DONE",death->cookie);

					if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION) 
					{
						list_del(&w->entry);
						kfree(death);
						binder_stats_deleted(BINDER_STAT_DEATH);
					} 
					else
						list_move(&w->entry, &proc->delivered_death);
					
					if (cmd == BR_DEAD_BINDER)
						goto done; /* DEAD_BINDER notifications can cause transactions */
				} 
				break;
		}

		if (!t)
			continue;

		BUG_ON(t->buffer == NULL);
		
		if (t->buffer->target_node) 
		{
			struct binder_node *target_node = t->buffer->target_node;
			tr.target.ptr = target_node->ptr;
			tr.cookie =  target_node->cookie;
			t->saved_priority = task_nice(current);
			
			if (t->priority < target_node->min_priority &&!(t->flags & TF_ONE_WAY))
				binder_set_nice(t->priority);
			else if (!(t->flags & TF_ONE_WAY) ||t->saved_priority > target_node->min_priority)
				binder_set_nice(target_node->min_priority);
			
			cmd = BR_TRANSACTION;
		} 
		else 
		{
			tr.target.ptr = NULL;
			tr.cookie = NULL;
			cmd = BR_REPLY;
		}
		
		tr.code = t->code;
		tr.flags = t->flags;
		tr.sender_euid = t->sender_euid;

		if (t->from) 
		{
			struct task_struct *sender = t->from->proc->tsk;
			
			tr.sender_pid = task_tgid_nr_ns(sender,current->nsproxy->pid_ns);
		} 
		else 
		{
			tr.sender_pid = 0;
		}

		tr.data_size = t->buffer->data_size;
		tr.offsets_size = t->buffer->offsets_size;
		tr.data.ptr.buffer = (void *)t->buffer->data +proc->user_buffer_offset;
		tr.data.ptr.offsets = tr.data.ptr.buffer + ALIGN(t->buffer->data_size, sizeof(void *));

		if (put_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		
		ptr += sizeof(uint32_t);
		
		if (copy_to_user(ptr, &tr, sizeof(tr)))
			return -EFAULT;
		
		ptr += sizeof(tr);

		binder_stat_br(proc, thread, cmd);
		
		binder_debug(BINDER_DEBUG_TRANSACTION,"binder: %d:%d %s %d %d:%d, cmd %d""size %zd-%zd ptr %p-%p\n",proc->pid, thread->pid,(cmd == BR_TRANSACTION) ? "BR_TRANSACTION" :"BR_REPLY",t->debug_id, t->from ? t->from->proc->pid : 0,t->from ? t->from->pid : 0, cmd,t->buffer->data_size, t->buffer->offsets_size,tr.data.ptr.buffer, tr.data.ptr.offsets);

		list_del(&t->work.entry);
		
		t->buffer->allow_user_free = 1;
		
		if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) 
		{
			t->to_parent = thread->transaction_stack;
			t->to_thread = thread;
			thread->transaction_stack = t;
		}
		else 
		{
			t->buffer->transaction = NULL;
			kfree(t);
			binder_stats_deleted(BINDER_STAT_TRANSACTION);
		}
		break;
	}

done:

	*consumed = ptr - buffer;
	if (proc->requested_threads + proc->ready_threads == 0 &&proc->requested_threads_started < proc->max_threads &&(thread->looper & (BINDER_LOOPER_STATE_REGISTERED |BINDER_LOOPER_STATE_ENTERED)) /* the user-space code fails to */ /*spawn a new thread if we leave this out */)
	{
		proc->requested_threads++;
		
		binder_debug(BINDER_DEBUG_THREADS,"binder: %d:%d BR_SPAWN_LOOPER\n",proc->pid, thread->pid);
		
		if (put_user(BR_SPAWN_LOOPER, (uint32_t __user *)buffer))
			return -EFAULT;
	}
	return 0;
}

static void binder_release_work(struct list_head *list)
{
	struct binder_work *w;
	
	while (!list_empty(list)) 
	{
		w = list_first_entry(list, struct binder_work, entry);
		list_del_init(&w->entry);
		
		switch (w->type) 
		{
			case BINDER_WORK_TRANSACTION: 
				{
					struct binder_transaction *t;

					t = container_of(w, struct binder_transaction, work);
					if (t->buffer->target_node && !(t->flags & TF_ONE_WAY))
						binder_send_failed_reply(t, BR_DEAD_REPLY);
				} 
				break;
				
			case BINDER_WORK_TRANSACTION_COMPLETE:
				{
					kfree(w);
					binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
				} 
				break;
				
			default:
				break;
		}
	}

}

static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
/*
	参数:
		1、proc : 传入由open 函数分配的内存数据结构
		
	返回:
		1、
		
	说明:
		1、此函数的执行过程
			A、首先在proc 的域成员threads 为根的红黑树中查找与当前进程pid 匹配的
				节点，如果找到就返回此节点
			B、经过A  步骤没找到，则此时分配一个binder_thread 的内存空间，同时对
				新分配的binder_thread 进行相应的初始化，并通过binder_thread 中的rb_node 域成员
				将此节点插入到proc 的域成员threads 为根的红黑树中
*/
	struct binder_thread *thread = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &proc->threads.rb_node;

	while (*p) 
	{
		parent = *p;
		
		thread = rb_entry(parent, struct binder_thread, rb_node);

		if (current->pid < thread->pid)
			p = &(*p)->rb_left;
		else if (current->pid > thread->pid)
			p = &(*p)->rb_right;
		else
			break;
	}
	
	if (*p == NULL) 
	{
		thread = kzalloc(sizeof(*thread), GFP_KERNEL);
		if (thread == NULL)
			return NULL;
		
		binder_stats_created(BINDER_STAT_THREAD);
		thread->proc = proc;
		thread->pid = current->pid;
		init_waitqueue_head(&thread->wait);
		INIT_LIST_HEAD(&thread->todo);
		
		rb_link_node(&thread->rb_node, parent, p);
		rb_insert_color(&thread->rb_node, &proc->threads); /* 将新分配的thread 数据结构插入到proc 的threads 域成员中*/

		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		thread->return_error = BR_OK;
		thread->return_error2 = BR_OK;
	}
	return thread;
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_transaction *t;
	struct binder_transaction *send_reply = NULL;
	int active_transactions = 0;

	rb_erase(&thread->rb_node, &proc->threads);
	t = thread->transaction_stack;
	
	if (t && t->to_thread == thread)
		send_reply = t;
	
	while (t) 
	{
		active_transactions++;
		binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,"binder: release %d:%d transaction %d ""%s, still active\n", proc->pid, thread->pid,t->debug_id,(t->to_thread == thread) ? "in" : "out");

		if (t->to_thread == thread) 
		{
			t->to_proc = NULL;
			t->to_thread = NULL;
			if (t->buffer) 
			{
				t->buffer->transaction = NULL;
				t->buffer = NULL;
			}
			t = t->to_parent;
		} 
		else if (t->from == thread) 
		{
			t->from = NULL;
			t = t->from_parent;
		} 
		else
			BUG();
	}
	
	if (send_reply)
		binder_send_failed_reply(send_reply, BR_DEAD_REPLY);
	
	binder_release_work(&thread->todo);
	kfree(thread);
	binder_stats_deleted(BINDER_STAT_THREAD);
	
	return active_transactions;
}

static unsigned int binder_poll(struct file *filp, struct poll_table_struct *wait)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread = NULL;
	int wait_for_proc_work;

	mutex_lock(&binder_lock);
	
	thread = binder_get_thread(proc);
	wait_for_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo) && thread->return_error == BR_OK;
	
	mutex_unlock(&binder_lock);

	if (wait_for_proc_work) 
	{
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
		
		poll_wait(filp, &proc->wait, wait);
		
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
	} 
	else 
	{
		if (binder_has_thread_work(thread))
			return POLLIN;
		
		poll_wait(filp, &thread->wait, wait);
		
		if (binder_has_thread_work(thread))
			return POLLIN;
	}
	return 0;
}

static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	int ret;
	struct binder_proc *proc = filp->private_data; /* 取出调用open 时分配的binder_proc 数据结构*/
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	/*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/

	/*
		wait_event_interruptible():
			该函数修改task 的状态为TASK_INTERRUPTIBLE，意味着该进程将不会继续运行
			直到被唤醒，然后被添加到等待队列wq 中。在wait_event_interruptible()中首先
			判断condition  是不是已经满足，如果是则直接返回0，否则调用__wait_event_interruptible()，
			并用__ret来存放返回值

		原型如下:
			#define wait_event_interruptible(wq, condition)          \
			({                                                       \
			    int __ret = 0;                                       \
			    if (!(condition))                                    \
			        __wait_event_interruptible(wq, condition, __ret);\
			    __ret;                                               \
			})

		__wait_event_interruptible 原型如下:
			__wait_event_interruptible()首先定义并初始化一个wait_queue_t变量__wait，其中数据为当前
			进程current，并把__wait入队。在无限循环中，__wait_event_interruptible()将本进程置为
			可中断的挂起状态，反复检查condition是否成立，如果成立则退出，如果不成
			立则继续休眠；条件满足后，即把本进程运行状态置为运行态，并将__wait 从
			等待队列中清除掉，从而进程能够调度运行。如果进程当前有异步信
			号(POSIX的)，则返回-ERESTARTSYS。
			----------------------------------------------------------------
			#define __wait_event_interruptible(wq, condition, ret)      \
			do {                                                        \
			    DEFINE_WAIT(__wait);                                    \
			    for (;;) {                                              \
			        prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE); \
			        if (condition)                                      \
			            break;                                          \
			        if (!signal_pending(current)) {                     \
			            schedule();                                     \
			            continue;                                       \
			        }                                                   \
			        ret = -ERESTARTSYS;                                 \
			        break;                                              \
			    }                                                       \
			    finish_wait(&wq, &__wait);                              \
			} while (0)

	*/

	/* 将调用ioctl 的进程挂起 caller 将挂起直到 service 返回*/
	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2); /* 如果条件满足则直接从此函数返回，否则函数进入睡眠状态，见上面说明*/
	if (ret)
		return ret;

	mutex_lock(&binder_lock);
	
	thread = binder_get_thread(proc); /* 根据当caller 进程消息获取该进程线程池数据结构，见函数的说明*/
	if (thread == NULL) 
	{
		ret = -ENOMEM;
		goto err;
	}

	switch (cmd) 
	{
		/*
			这其中最常用的命令是BINDER_WRITE_READ。该命令的参数包括两部分数据：一部分是向Binder写入
			的数据，一部分是要从 Binder读出的数据，驱动程序先处理写部分再处理读部分。这样安排
			的好处是应用程序可以很灵活地处理命令的同步或异步。例如若要发送异步命令可以只填 
			入写部分而将read_size置成0；若要只从Binder获得数据可以将写部分置空即write_size置成0；若要发
			送请求并同步等待返回数据可 以将两部分都置上。
		*/
		case BINDER_WRITE_READ: 
			{
				struct binder_write_read bwr;
				
				if (size != sizeof(struct binder_write_read)) /* 计算传入的用户空间数据的长度是否正确，即此case 中用户空间传入的一定要是一个binder_write_read 的数据结构的数据，否则就错了*/
				{ 
					ret = -EINVAL;
					goto err;
				}
				
				if (copy_from_user(&bwr, ubuf, sizeof(bwr))) /* 从用户空间将数据拷贝到内核空间来*/
				{
					ret = -EFAULT;
					goto err;
				}
				
				binder_debug(BINDER_DEBUG_READ_WRITE,"binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",proc->pid, thread->pid, bwr.write_size, bwr.write_buffer,bwr.read_size, bwr.read_buffer);

				if (bwr.write_size > 0) /* 如果要写的数据长度大于0，相当于要写入数据，所以调用函数进行写数据*/
				{	
					ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
					if (ret < 0) 
					{
						bwr.read_consumed = 0;
						if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
							ret = -EFAULT;
						goto err;
					}
				}
				
				if (bwr.read_size > 0) /* 如果要读的数据长度大于0，相当于要读出数据，所以调用函数进行读数据*/
				{ 	
					ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
					
					if (!list_empty(&proc->todo))
						wake_up_interruptible(&proc->wait); /* 恢复挂起的caller进程*/
					
					if (ret < 0) 
					{
						if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
							ret = -EFAULT;
						goto err;
					}
				}
				
				binder_debug(BINDER_DEBUG_READ_WRITE,"binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",proc->pid, thread->pid, bwr.write_consumed, bwr.write_size, bwr.read_consumed, bwr.read_size);
				if (copy_to_user(ubuf, &bwr, sizeof(bwr))) 
				{
					ret = -EFAULT;
					goto err;
				}
				break;
			}
		
		case BINDER_SET_MAX_THREADS:
			if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) /* 用用户空间传入的数据对其进行设置*/
			{
				ret = -EINVAL;
				goto err;
			}
			break;
		
		case BINDER_SET_CONTEXT_MGR: /* 将此打开的binder 设置为service ，只能设置一个进程为service ，见android\source\frameworks\base\cmds\servicemanager\Service_manager.c  => main => binder_become_context_manager  的调用*/

			if (binder_context_mgr_node != NULL) /* 判断serviceMagager  进程是否已经创建了*/
			{
				printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
				ret = -EBUSY;
				goto err;
			}
			
			if (binder_context_mgr_uid != -1) /* 判断serviceMagager  进程是否已经创建了*/
			{
				if (binder_context_mgr_uid != current->cred->euid) 
				{
					printk(KERN_ERR "binder: BINDER_SET_" "CONTEXT_MGR bad uid %d != %d\n",current->cred->euid,binder_context_mgr_uid);
					ret = -EPERM;
					goto err;
				}
			} 
			else
				binder_context_mgr_uid = current->cred->euid;
			
			binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
			
			if (binder_context_mgr_node == NULL) 
			{
				ret = -ENOMEM;
				goto err;
			}
			
			binder_context_mgr_node->local_weak_refs++;
			binder_context_mgr_node->local_strong_refs++;
			binder_context_mgr_node->has_strong_ref = 1;
			binder_context_mgr_node->has_weak_ref = 1;
			break;
			
		case BINDER_THREAD_EXIT:
			binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d exit\n",proc->pid, thread->pid);
			binder_free_thread(proc, thread);
			thread = NULL;
			break;
			
		case BINDER_VERSION:
			if (size != sizeof(struct binder_version)) 
			{
				ret = -EINVAL;
				goto err;
			}
			
			if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version)) 
			{
				ret = -EINVAL;
				goto err;
			}
			break;
			
		default:
			ret = -EINVAL;
			goto err;
	}
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	
	mutex_unlock(&binder_lock);
	wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	
	if (ret && ret != -ERESTARTSYS)
		printk(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);
	
	return ret;
}

static void binder_vma_open(struct vm_area_struct *vma)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc = vma->vm_private_data;
	binder_debug(BINDER_DEBUG_OPEN_CLOSE,"binder: %d open vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",proc->pid, vma->vm_start, vma->vm_end,(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,(unsigned long)pgprot_val(vma->vm_page_prot));
	dump_stack();
}

static void binder_vma_close(struct vm_area_struct *vma)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc = vma->vm_private_data;
	binder_debug(BINDER_DEBUG_OPEN_CLOSE,"binder: %d close vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",proc->pid, vma->vm_start, vma->vm_end,(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,(unsigned long)pgprot_val(vma->vm_page_prot));
	proc->vma = NULL;
	binder_defer_work(proc, BINDER_DEFERRED_PUT_FILES);
}

static struct vm_operations_struct binder_vm_ops = {
	.open = binder_vma_open,
	.close = binder_vma_close,
};


static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、执行过程:
			A、如果传入的vma 中的结束地址与起始地址之间的范围大于4M 了，则强制其变成4M
			B、对虚拟地址数据结构中的标志进行设定
			C、如果该proc ( 进程调用binder_open 时获得的) 的buffer 不为空，则说明此proc ( 与调用binder_open 的进程相对应)
				已经被执行过地址映射了，即调用过此函数了
			D、
*/
	int ret;
	struct vm_struct *area;
	struct binder_proc *proc = filp->private_data;
	const char *failure_string;
	struct binder_buffer *buffer;

	if ((vma->vm_end - vma->vm_start) > SZ_4M)/* 判断4M 边界*/
		vma->vm_end = vma->vm_start + SZ_4M;

	binder_debug(BINDER_DEBUG_OPEN_CLOSE,
				     "binder_mmap: %d %lx-%lx (%ld K) vma %lx pagep %lx\n",
				     proc->pid, vma->vm_start, vma->vm_end,
				     (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
				     (unsigned long)pgprot_val(vma->vm_page_prot));

	if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) 
	{
		ret = -EPERM;
		failure_string = "bad vm_flags";
		goto err_bad_arg;
	}
	
	vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE; /* 更新虚拟空间数据结构的标志*/

	if (proc->buffer)/* 判断此进程是否已经调用过此函数进行过内存分配了*/
	{
		ret = -EBUSY;
		failure_string = "already mapped";
		goto err_already_mapped;
	}

	/*
		函数get_vm_area 在线性地址VMALLOC_START  和VMALLOC_END  之间查找一个空闲的线性地址空间。
		注意此函数只是分配了vm_struct 数据结构的内存空间，并将此结构添加到了全局vmlist 的
		链表中，并没有实际分配真正的buffer 所使用的页面空间
		关于函数的get_vm_area 说明可见linux 内核学习笔记
	*/
	area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP); 
	if (area == NULL) 
	{
		ret = -ENOMEM;
		failure_string = "get_vm_area";
		goto err_get_vm_area_failed;
	}

	/*
		此处的分析
		
		用户需要映射的虚拟起始地址为vma->vm_start，虚拟结束地址为vma->vm_end，而经过函数
		get_vm_area 的调用后获得到的虚拟起始地址为area->addr，具体见linux 内核学习笔记中对此
		函数的分析( 初步分析调用函数get_vm_area 只是传入了要分配的虚拟空间的大小，所以
		函数内部就会根据这个空间的大小在全局虚拟地址数据结构链表中找到合适的地方
		，然后分配一个虚拟数据结构，并按照链表中的所有虚拟地址的排序等确定虚拟数据
		结构中的起始地址，即area->addr) 。所以映射的虚拟地址和分配后的起始地址，
		即vma->vm_start 与area->addr 会存在一定的偏差，所以proc->user_buffer_offset 就是用于保存此值的
	*/
	proc->buffer = area->addr;
	proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;

#ifdef CONFIG_CPU_CACHE_VIPT
	if (cache_is_vipt_aliasing()) 
	{
		while (CACHE_COLOUR((vma->vm_start ^ (uint32_t)proc->buffer)))
		{
			printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p bad alignment\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);
			vma->vm_start += PAGE_SIZE;
		}
	}
#endif
	
	/*
		分配指针数组的内存，数组中的每个元素为一个指针，后续代码会设置将每个指针
		指向一个实际的物理内存的页面地址

		根据起始虚地址、结束虚地址，通过计算就可以知道实际需要多少个物理页面，
		然后就分配多少个指针元素，这些指针元素构成一个数组，有proc 的域成员pages 保存
	*/
	proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
	if (proc->pages == NULL) 
	{
		ret = -ENOMEM;
		failure_string = "alloc page array";
		goto err_alloc_pages_failed;
	}
	
	proc->buffer_size = vma->vm_end - vma->vm_start;

/*
	struct vm_operations_struct
	{
		void (*open)(struct vm_area_struct * area);
		void (*close)(struct vm_area_struct * area);
		struct page * (*nopage)(struct vm_area_struct * area, unsigned long address, int write_access);
	};
	
	结构中全是函数指针。其中open、close、nopage  分别用于虚存区间的打开、关闭和建立映射。为
	什么要有这些函数呢? 这是因为对于不同的虚存区间可能会需要一些不同的附加操作。函数指针
	nopage 指示当因( 虚存) 页面不在内存中而引起"页面出错" (page fault) 异常时所应调用的函数。
*/

	vma->vm_ops = &binder_vm_ops; /* 设定vm_area_struct 数据结构的操作函数表，*/
	vma->vm_private_data = proc; /* 将数据结构vm_area_struct 中的私有数据设置为proc 值*/

	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) /* 见函数内部分析*/
	{
		ret = -ENOMEM;
		failure_string = "alloc small buf";
		goto err_alloc_small_buf_failed;
	}
	
	buffer = proc->buffer;
	INIT_LIST_HEAD(&proc->buffers);
	list_add(&buffer->entry, &proc->buffers);
	buffer->free = 1;
	binder_insert_free_buffer(proc, buffer);
	proc->free_async_space = proc->buffer_size / 2;
	barrier();
	proc->files = get_files_struct(current);
	proc->vma = vma;

	/*printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);*/
	return 0;

err_alloc_small_buf_failed:
	
	kfree(proc->pages);
	proc->pages = NULL;

	
err_alloc_pages_failed:
	
	vfree(proc->buffer);
	proc->buffer = NULL;

	
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
	
	printk(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n",proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);

	return ret;
}

static int binder_open(struct inode *nodp, struct file *filp)
{
/*
	此函数用于打开binder 的设备文件/dev/binder
	任何一个进程及其内的所有线程都可以打开一个binder 设备

	此函数的过程:
	首先分配一个binder_proc 类型的内存空间，然后将当前进程的信息保存到此数据结构中，并
	对其内部的相关变量进行初始化，然后将这个数据结构添加到由binder_procs 所保存的全局
	链表中

	1、需要创建并分配一个binder_proc 空间来保存binder 数据
	2、增加当前线程/进程的引用计数，并赋值给binder_proc 的tsk 字段
	3、初始化binder_proc 队列，其中主要包括使用INIT_LIST_HEAD 初始化链表头todo，使用init_waitqueue_head初始化等待
		队列wait，设置默认优先级别(default_priority)为当前进程的nice 值(通过task nice 得到当前进程的nice 值)
	4、增加BINDER_STAT_PROC的对象计数，并通过hlist_add_head把创建的binder_proc对象添加到全局的binder_proc 的哈希表
		中，这样一来，任何一个进程就都可以访问到其他进程的binder_proc 对象了
	5、把当前进程(或线程) 的线程组的pid (pid 指向线程id) 赋值给proc 的pid 字段，可以理解为一个进程id ( thread_group
		指向线程组中的第一个线程的task_struct 结构)，同时把创建的binder_proc 对象指针赋值给filp 的private_data 对象
		保存起来
	6、在binder proc 目录中创建只读文件/proc/binder/proc/$pid，用来输出当前binder proc 对象的状态，文件名以pid 命名，
		但需要注意的是，该pid 字段并不是当前进程/ 线程的id，而是线程组的pid，也就是线程组中第一个线
		程pid (因为是将current->grout_leader->pid 赋值给该pid 字段的)。另外，在创建该文件时，同样也指定了操作该
		文件的函数接口为binder_read_proc_proc ，其参数正是我们创建的binder_proc 对象proc，即此文件对应的操作接口
		函数为上面分配的binder_proc 结构
*/
	struct binder_proc *proc;

	binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_open: %d:%d\n",  current->group_leader->pid, current->pid);

	proc = kzalloc(sizeof(*proc), GFP_KERNEL); /* 为binder_proc 分配内存空间*/
	if (proc == NULL)
		return -ENOMEM;
	
	get_task_struct(current); /* 增加调用此函数的进程控制块的引用计数*/
	
	proc->tsk = current; /* */
	
	INIT_LIST_HEAD(&proc->todo);
	
	init_waitqueue_head(&proc->wait);
	
	proc->default_priority = task_nice(current);
	
	mutex_lock(&binder_lock);
	
	binder_stats_created(BINDER_STAT_PROC);
	
	hlist_add_head(&proc->proc_node, &binder_procs);/* 通过proc 的域成员proc_node 将此新分配的proc 数据结构添加到全局哈希表binder_procs 中*/

	proc->pid = current->group_leader->pid;
	
	INIT_LIST_HEAD(&proc->delivered_death);
	
	filp->private_data = proc;
	
	mutex_unlock(&binder_lock);

	/* 创建只读文件/proc/binder/proc/$pid */
	if (binder_debugfs_dir_entry_proc) 
	{
		char strbuf[11];
		
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		
		proc->debugfs_entry = debugfs_create_file(strbuf, S_IRUGO,binder_debugfs_dir_entry_proc, proc, &binder_proc_fops);
	}

	return 0;
}

static int binder_flush(struct file *filp, fl_owner_t id)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc = filp->private_data;

	binder_defer_work(proc, BINDER_DEFERRED_FLUSH);

	return 0;
}

static void binder_deferred_flush(struct binder_proc *proc)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct rb_node *n;
	int wake_count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) 
	{
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		
		if (thread->looper & BINDER_LOOPER_STATE_WAITING) 
		{
			wake_up_interruptible(&thread->wait);
			wake_count++;
		}
	}
	
	wake_up_interruptible_all(&proc->wait);

	binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_flush: %d woke %d threads\n", proc->pid, wake_count);
}

static int binder_release(struct inode *nodp, struct file *filp)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc = filp->private_data;
	debugfs_remove(proc->debugfs_entry); /* 删除open 函数中创建的/proc/binder/proc/$pid  文件*/
	binder_defer_work(proc, BINDER_DEFERRED_RELEASE);

	return 0;
}

static void binder_deferred_release(struct binder_proc *proc)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct hlist_node *pos;
	struct binder_transaction *t;
	struct rb_node *n;
	int threads, nodes, incoming_refs, outgoing_refs, buffers, active_transactions, page_count;

	BUG_ON(proc->vma);
	BUG_ON(proc->files);

	hlist_del(&proc->proc_node);
	
	if (binder_context_mgr_node && binder_context_mgr_node->proc == proc) 
	{
		binder_debug(BINDER_DEBUG_DEAD_BINDER, "binder_release: %d context_mgr_node gone\n", proc->pid);
		binder_context_mgr_node = NULL;
	}

	threads = 0;
	active_transactions = 0;
	while ((n = rb_first(&proc->threads))) 
	{
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		threads++;
		active_transactions += binder_free_thread(proc, thread);
	}
	
	nodes = 0;
	incoming_refs = 0;
	while ((n = rb_first(&proc->nodes))) 
	{
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);

		nodes++;
		rb_erase(&node->rb_node, &proc->nodes);
		list_del_init(&node->work.entry);
		
		if (hlist_empty(&node->refs)) 
		{
			kfree(node);
			binder_stats_deleted(BINDER_STAT_NODE);
		}
		else
		{
			struct binder_ref *ref;
			int death = 0;

			node->proc = NULL;
			node->local_strong_refs = 0;
			node->local_weak_refs = 0;
			hlist_add_head(&node->dead_node, &binder_dead_nodes);

			hlist_for_each_entry(ref, pos, &node->refs, node_entry) 
			{
				incoming_refs++;
				if (ref->death) 
				{
					death++;
					if (list_empty(&ref->death->work.entry)) 
					{
						ref->death->work.type = BINDER_WORK_DEAD_BINDER;
						list_add_tail(&ref->death->work.entry, &ref->proc->todo);
						wake_up_interruptible(&ref->proc->wait);
					}
					else
						BUG();
				}
			}
			
			binder_debug(BINDER_DEBUG_DEAD_BINDER,
						     "binder: node %d now dead, "
						     "refs %d, death %d\n", node->debug_id,
						     incoming_refs, death);
		}
	}
	
	outgoing_refs = 0;
	
	while ((n = rb_first(&proc->refs_by_desc))) 
	{
		struct binder_ref *ref = rb_entry(n, struct binder_ref,  rb_node_desc);
		outgoing_refs++;
		binder_delete_ref(ref);
	}
	
	binder_release_work(&proc->todo);
	buffers = 0;

	while ((n = rb_first(&proc->allocated_buffers))) 
	{
		struct binder_buffer *buffer = rb_entry(n, struct binder_buffer, rb_node);
		
		t = buffer->transaction;
		
		if (t) 
		{
			t->buffer = NULL;
			buffer->transaction = NULL;
			printk(KERN_ERR "binder: release proc %d, " "transaction %d, not freed\n", proc->pid, t->debug_id);
			/*BUG();*/
		}
		
		binder_free_buf(proc, buffer);
		buffers++;
	}

	binder_stats_deleted(BINDER_STAT_PROC);

	page_count = 0;
	if (proc->pages) 
	{
		int i;
		for (i = 0; i < proc->buffer_size / PAGE_SIZE; i++) 
		{
			if (proc->pages[i])
			{
				void *page_addr = proc->buffer + i * PAGE_SIZE;
				
				binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
							     "binder_release: %d: "
							     "page %d at %p not freed\n",
							     proc->pid, i,
							     page_addr);
				
				unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
				
				__free_page(proc->pages[i]);
				page_count++;
			}
		}
		
		kfree(proc->pages);
		vfree(proc->buffer);
	}

	put_task_struct(proc->tsk);

	binder_debug(BINDER_DEBUG_OPEN_CLOSE,
				     "binder_release: %d threads %d, nodes %d (ref %d), "
				     "refs %d, active transactions %d, buffers %d, "
				     "pages %d\n",
				     proc->pid, threads, nodes, incoming_refs, outgoing_refs,
				     active_transactions, buffers, page_count);

	kfree(proc);
}

static void binder_deferred_func(struct work_struct *work)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc;
	struct files_struct *files;

	int defer;
	do
	{
		mutex_lock(&binder_lock);
		mutex_lock(&binder_deferred_lock);
		
		if (!hlist_empty(&binder_deferred_list)) 
		{
			proc = hlist_entry(binder_deferred_list.first, struct binder_proc, deferred_work_node);
			hlist_del_init(&proc->deferred_work_node);
			defer = proc->deferred_work;
			proc->deferred_work = 0;
		} 
		else 
		{
			proc = NULL;
			defer = 0;
		}
		
		mutex_unlock(&binder_deferred_lock);

		files = NULL;
		if (defer & BINDER_DEFERRED_PUT_FILES)
		{
			files = proc->files;
			if (files)
				proc->files = NULL;
		}

		if (defer & BINDER_DEFERRED_FLUSH)
			binder_deferred_flush(proc);

		if (defer & BINDER_DEFERRED_RELEASE)
			binder_deferred_release(proc); /* frees proc */

		mutex_unlock(&binder_lock);
		if (files)
			put_files_struct(files);
	} while (proc);
}

static DECLARE_WORK(binder_deferred_work, binder_deferred_func);

static void binder_defer_work(struct binder_proc *proc, enum binder_deferred_state defer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mutex_lock(&binder_deferred_lock);
	proc->deferred_work |= defer;
	if (hlist_unhashed(&proc->deferred_work_node))
	{
		hlist_add_head(&proc->deferred_work_node, &binder_deferred_list);
		queue_work(binder_deferred_workqueue, &binder_deferred_work);
	}
	mutex_unlock(&binder_deferred_lock);
}

static void print_binder_transaction(struct seq_file *m, const char *prefix, struct binder_transaction *t)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	seq_printf( m,
			   "%s %d: %p from %d:%d to %d:%d code %x flags %x pri %ld r%d",
			   prefix, t->debug_id, t,
			   t->from ? t->from->proc->pid : 0,
			   t->from ? t->from->pid : 0,
			   t->to_proc ? t->to_proc->pid : 0,
			   t->to_thread ? t->to_thread->pid : 0,
			   t->code, t->flags, t->priority, t->need_reply);
	
	if (t->buffer == NULL) 
	{
		seq_puts(m, " buffer free\n");
		return;
	}
	
	if (t->buffer->target_node)
		seq_printf(m, " node %d", t->buffer->target_node->debug_id);
	
	seq_printf(m, " size %zd:%zd data %p\n", t->buffer->data_size, t->buffer->offsets_size, t->buffer->data);
}

static void print_binder_buffer(struct seq_file *m, const char *prefix, struct binder_buffer *buffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	seq_printf(m, "%s %d: %p size %zd:%zd %s\n",
				   prefix, buffer->debug_id, buffer->data,
				   buffer->data_size, buffer->offsets_size,
				   buffer->transaction ? "active" : "delivered");
}

static void print_binder_work(struct seq_file *m, const char *prefix,  const char *transaction_prefix, struct binder_work *w)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_node *node;
	struct binder_transaction *t;

	switch (w->type)
	{
		case BINDER_WORK_TRANSACTION:
			t = container_of(w, struct binder_transaction, work);
			print_binder_transaction(m, transaction_prefix, t);
			break;
			
		case BINDER_WORK_TRANSACTION_COMPLETE:
			seq_printf(m, "%stransaction complete\n", prefix);
			break;
			
		case BINDER_WORK_NODE:
			node = container_of(w, struct binder_node, work);
			seq_printf(m, "%snode work %d: u%p c%p\n", prefix, node->debug_id, node->ptr, node->cookie);
			break;
			
		case BINDER_WORK_DEAD_BINDER:
			seq_printf(m, "%shas dead binder\n", prefix);
			break;
			
		case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
			seq_printf(m, "%shas cleared dead binder\n", prefix);
			break;
			
		case BINDER_WORK_CLEAR_DEATH_NOTIFICATION:
			seq_printf(m, "%shas cleared death notification\n", prefix);
			break;
			
		default:
			seq_printf(m, "%sunknown work: type %d\n", prefix, w->type);
			break;
	}
}

static void print_binder_thread(struct seq_file *m, struct binder_thread *thread, int print_always)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_transaction *t;
	struct binder_work *w;
	size_t start_pos = m->count;
	size_t header_pos;

	seq_printf(m, "  thread %d: l %02x\n", thread->pid, thread->looper);
	header_pos = m->count;
	t = thread->transaction_stack;
	
	while (t) 
	{
		if (t->from == thread) 
		{
			print_binder_transaction(m, "    outgoing transaction", t);
			t = t->from_parent;
		} 
		else if (t->to_thread == thread) 
		{
			print_binder_transaction(m, "    incoming transaction", t);
			t = t->to_parent;
		} 
		else 
		{
			print_binder_transaction(m, "    bad transaction", t);
			t = NULL;
		}
	}
	
	list_for_each_entry(w, &thread->todo, entry) 
	{
		print_binder_work(m, "    ", "    pending transaction", w);
	}
	
	if (!print_always && m->count == header_pos)
		m->count = start_pos;
}

static void print_binder_node(struct seq_file *m, struct binder_node *node)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_ref *ref;
	struct hlist_node *pos;
	struct binder_work *w;
	int count;

	count = 0;
	hlist_for_each_entry(ref, pos, &node->refs, node_entry)
		count++;

	seq_printf(m, "  node %d: u%p c%p hs %d hw %d ls %d lw %d is %d iw %d",
				   node->debug_id, node->ptr, node->cookie,
				   node->has_strong_ref, node->has_weak_ref,
				   node->local_strong_refs, node->local_weak_refs,
				   node->internal_strong_refs, count);
	
	if (count) 
	{
		seq_puts(m, " proc");
		
		hlist_for_each_entry(ref, pos, &node->refs, node_entry)
			seq_printf(m, " %d", ref->proc->pid);
	}
	
	seq_puts(m, "\n");
	
	list_for_each_entry(w, &node->async_todo, entry)
		print_binder_work(m, "    ", "    pending async transaction", w);
}

static void print_binder_ref(struct seq_file *m, struct binder_ref *ref)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	seq_printf(m, "  ref %d: desc %d %snode %d s %d w %d d %p\n", ref->debug_id, ref->desc, ref->node->proc ? "" : "dead ", ref->node->debug_id, ref->strong, ref->weak, ref->death);
}

static void print_binder_proc(struct seq_file *m, struct binder_proc *proc, int print_all)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_work *w;
	struct rb_node *n;
	size_t start_pos = m->count;
	size_t header_pos;

	seq_printf(m, "proc %d\n", proc->pid);
	header_pos = m->count;

	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n))
		print_binder_thread(m, rb_entry(n, struct binder_thread,rb_node), print_all);
	
	for (n = rb_first(&proc->nodes); n != NULL; n = rb_next(n)) 
	{
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);
		
		if (print_all || node->has_async_transaction)
			print_binder_node(m, node);
	}
	if (print_all) 
	{
		for (n = rb_first(&proc->refs_by_desc);  n != NULL;  n = rb_next(n))
			print_binder_ref(m, rb_entry(n, struct binder_ref, rb_node_desc));
	}
	
	for (n = rb_first(&proc->allocated_buffers); n != NULL; n = rb_next(n))
		print_binder_buffer(m, "  buffer", rb_entry(n, struct binder_buffer, rb_node));
	
	list_for_each_entry(w, &proc->todo, entry)
		print_binder_work(m, "  ", "  pending transaction", w);
	
	list_for_each_entry(w, &proc->delivered_death, entry) 
	{
		seq_puts(m, "  has delivered dead binder\n");
		break;
	}
	
	if (!print_all && m->count == header_pos)
		m->count = start_pos;
}

static const char *binder_return_strings[] = {
	"BR_ERROR",
	"BR_OK",
	"BR_TRANSACTION",
	"BR_REPLY",
	"BR_ACQUIRE_RESULT",
	"BR_DEAD_REPLY",
	"BR_TRANSACTION_COMPLETE",
	"BR_INCREFS",
	"BR_ACQUIRE",
	"BR_RELEASE",
	"BR_DECREFS",
	"BR_ATTEMPT_ACQUIRE",
	"BR_NOOP",
	"BR_SPAWN_LOOPER",
	"BR_FINISHED",
	"BR_DEAD_BINDER",
	"BR_CLEAR_DEATH_NOTIFICATION_DONE",
	"BR_FAILED_REPLY"
};

static const char *binder_command_strings[] = {
	"BC_TRANSACTION",
	"BC_REPLY",
	"BC_ACQUIRE_RESULT",
	"BC_FREE_BUFFER",
	"BC_INCREFS",
	"BC_ACQUIRE",
	"BC_RELEASE",
	"BC_DECREFS",
	"BC_INCREFS_DONE",
	"BC_ACQUIRE_DONE",
	"BC_ATTEMPT_ACQUIRE",
	"BC_REGISTER_LOOPER",
	"BC_ENTER_LOOPER",
	"BC_EXIT_LOOPER",
	"BC_REQUEST_DEATH_NOTIFICATION",
	"BC_CLEAR_DEATH_NOTIFICATION",
	"BC_DEAD_BINDER_DONE"
};

static const char *binder_objstat_strings[] = {
	"proc",
	"thread",
	"node",
	"ref",
	"death",
	"transaction",
	"transaction_complete"
};

static void print_binder_stats(struct seq_file *m, const char *prefix, struct binder_stats *stats)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(stats->bc) !=  ARRAY_SIZE(binder_command_strings));
	
	for (i = 0; i < ARRAY_SIZE(stats->bc); i++) 
	{
		if (stats->bc[i])
			seq_printf(m, "%s%s: %d\n", prefix, binder_command_strings[i], stats->bc[i]);
	}

	BUILD_BUG_ON(ARRAY_SIZE(stats->br) != ARRAY_SIZE(binder_return_strings));
	
	for (i = 0; i < ARRAY_SIZE(stats->br); i++) 
	{
		if (stats->br[i])
			seq_printf(m, "%s%s: %d\n", prefix, binder_return_strings[i], stats->br[i]);
	}

	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(binder_objstat_strings));
	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(stats->obj_deleted));
	
	for (i = 0; i < ARRAY_SIZE(stats->obj_created); i++) 
	{
		if (stats->obj_created[i] || stats->obj_deleted[i])
			seq_printf(m, "%s%s: active %d total %d\n", prefix, binder_objstat_strings[i], stats->obj_created[i] - stats->obj_deleted[i], stats->obj_created[i]);
	}
}

static void print_binder_proc_stats(struct seq_file *m, struct binder_proc *proc)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_work *w;
	struct rb_node *n;
	int count, strong, weak;

	seq_printf(m, "proc %d\n", proc->pid);
	
	count = 0;
	
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n))
		count++;
	
	seq_printf(m, "  threads: %d\n", count);
	seq_printf(m, "  requested threads: %d+%d/%d\n"
				"  ready threads %d\n"
				"  free async space %zd\n", proc->requested_threads,
				proc->requested_threads_started, proc->max_threads,
				proc->ready_threads, proc->free_async_space);
	
	count = 0;
	
	for (n = rb_first(&proc->nodes); n != NULL; n = rb_next(n))
		count++;
	
	seq_printf(m, "  nodes: %d\n", count);
	count = 0;
	strong = 0;
	weak = 0;
	
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) 
	{
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		count++;
		strong += ref->strong;
		weak += ref->weak;
	}
	
	seq_printf(m, "  refs: %d s %d w %d\n", count, strong, weak);

	count = 0;
	for (n = rb_first(&proc->allocated_buffers); n != NULL; n = rb_next(n))
		count++;
	
	seq_printf(m, "  buffers: %d\n", count);

	count = 0;
	list_for_each_entry(w, &proc->todo, entry) 
	{
		switch (w->type) 
		{
			case BINDER_WORK_TRANSACTION:
				count++;
				break;
				
			default:
				break;
		}
	}
	
	seq_printf(m, "  pending transactions: %d\n", count);

	print_binder_stats(m, "  ", &proc->stats);
}


static int binder_state_show(struct seq_file *m, void *unused)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc;
	struct hlist_node *pos;
	struct binder_node *node;
	int do_lock = !binder_debug_no_lock;

	if (do_lock)
		mutex_lock(&binder_lock);

	seq_puts(m, "binder state:\n");

	if (!hlist_empty(&binder_dead_nodes))
		seq_puts(m, "dead nodes:\n");
	
	hlist_for_each_entry(node, pos, &binder_dead_nodes, dead_node)
		print_binder_node(m, node);

	hlist_for_each_entry(proc, pos, &binder_procs, proc_node)
		print_binder_proc(m, proc, 1);
	
	if (do_lock)
		mutex_unlock(&binder_lock);
	
	return 0;
}

static int binder_stats_show(struct seq_file *m, void *unused)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc;
	struct hlist_node *pos;
	int do_lock = !binder_debug_no_lock;

	if (do_lock)
		mutex_lock(&binder_lock);

	seq_puts(m, "binder stats:\n");

	print_binder_stats(m, "", &binder_stats);

	hlist_for_each_entry(proc, pos, &binder_procs, proc_node)
		print_binder_proc_stats(m, proc);
	
	if (do_lock)
		mutex_unlock(&binder_lock);
	
	return 0;
}

static int binder_transactions_show(struct seq_file *m, void *unused)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc;
	struct hlist_node *pos;
	int do_lock = !binder_debug_no_lock;

	if (do_lock)
		mutex_lock(&binder_lock);

	seq_puts(m, "binder transactions:\n");
	hlist_for_each_entry(proc, pos, &binder_procs, proc_node)
		print_binder_proc(m, proc, 0);
	
	if (do_lock)
		mutex_unlock(&binder_lock);
	
	return 0;
}

static int binder_proc_show(struct seq_file *m, void *unused)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_proc *proc = m->private;
	int do_lock = !binder_debug_no_lock;

	if (do_lock)
		mutex_lock(&binder_lock);
	
	seq_puts(m, "binder proc state:\n");
	
	print_binder_proc(m, proc, 1);
	
	if (do_lock)
		mutex_unlock(&binder_lock);
	
	return 0;
}

static void print_binder_transaction_log_entry(struct seq_file *m, struct binder_transaction_log_entry *e)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	seq_printf(m,
			   "%d: %s from %d:%d to %d:%d node %d handle %d size %d:%d\n",
			   e->debug_id, (e->call_type == 2) ? "reply" :
			   ((e->call_type == 1) ? "async" : "call "), e->from_proc,
			   e->from_thread, e->to_proc, e->to_thread, e->to_node,
			   e->target_handle, e->data_size, e->offsets_size);
}

static int binder_transaction_log_show(struct seq_file *m, void *unused)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_transaction_log *log = m->private;
	int i;

	if (log->full) 
	{
		for (i = log->next; i < ARRAY_SIZE(log->entry); i++)
			print_binder_transaction_log_entry(m, &log->entry[i]);
	}
	
	for (i = 0; i < log->next; i++)
		print_binder_transaction_log_entry(m, &log->entry[i]);
	
	return 0;
}


static const struct file_operations binder_fops = 
{
	.owner 			= THIS_MODULE,
	.poll 			= binder_poll,
	.unlocked_ioctl 	= binder_ioctl,
	.mmap 			= binder_mmap,
	.open 			= binder_open,
	.flush 			= binder_flush,
	.release 			= binder_release,
};


static struct miscdevice binder_miscdev = 
{
	.minor 	= MISC_DYNAMIC_MINOR,
	.name 	= "binder",
	.fops 	= &binder_fops
};

BINDER_DEBUG_ENTRY(state);
BINDER_DEBUG_ENTRY(stats);
BINDER_DEBUG_ENTRY(transactions);
BINDER_DEBUG_ENTRY(transaction_log);

static int __init binder_init(void)
{
	int ret;

	binder_deferred_workqueue = create_singlethread_workqueue("binder");
	if (!binder_deferred_workqueue)
		return -ENOMEM;

	/* 创建binder 的目录项，书上说此节点为/proc/binder ，有待于实际测试*/
	binder_debugfs_dir_entry_root = debugfs_create_dir("binder", NULL);

	/* 创建proc 文件系统的binder 目录项，书上说此节点为/proc/binder/proc ，有待于实际测试*/
	if (binder_debugfs_dir_entry_root)
		binder_debugfs_dir_entry_proc = debugfs_create_dir("proc", binder_debugfs_dir_entry_root);

	/* 注册misc 设备，设备节点为/dev/binder ，主设备号为10，该节点由init 进程在handle_device_fd(device_fd) 函数中调用handle_device_event(&uevent) 函数执行其中uevent-netlink 事件在"/dev" 目录下创建*/
	ret = misc_register(&binder_miscdev);
	
	if (binder_debugfs_dir_entry_root)
	{
		/*
			debugfs 文件系统
			
			1 Debugfs简介
				Debugfs文件系统目的是为开发人员提供更多内核数据,方便调试内容. 我们知
				道/proc文件系统关注的是进程信息，/sysfs关注是one-value-per-file策略集，而Debugfs文
				件系统没有如此多限制，可是任何内核要输出的信息。

			2 Debugfs使用
				2.1 安装文件系统
			    		Debugfs没有物理设备，其挂载方式：
			   		mount -t debugfs none /sys/kernel/debug
		*/
		/* 创建下面几个文件 */
		debugfs_create_file("state",						/* ---> /proc/binder/state */
				    S_IRUGO,
				    binder_debugfs_dir_entry_root,
				    NULL,
				    &binder_state_fops);
		
		debugfs_create_file("stats",						/* ---> /proc/binder/stats */
				    S_IRUGO,
				    binder_debugfs_dir_entry_root,
				    NULL,
				    &binder_stats_fops);
		
		debugfs_create_file("transactions",				/* ---> /proc/binder/transactions */
				    S_IRUGO,
				    binder_debugfs_dir_entry_root,
				    NULL,
				    &binder_transactions_fops);
		
		debugfs_create_file("transaction_log",				/* ---> /proc/binder/transaction_log */
				    S_IRUGO,
				    binder_debugfs_dir_entry_root,
				    &binder_transaction_log,
				    &binder_transaction_log_fops);
		
		debugfs_create_file("failed_transaction_log",		/* ---> /proc/binder/failed_transaction_log */
				    S_IRUGO,
				    binder_debugfs_dir_entry_root,
				    &binder_transaction_log_failed,
				    &binder_transaction_log_fops);
	}
	return ret;
}

device_initcall(binder_init);

MODULE_LICENSE("GPL v2");
