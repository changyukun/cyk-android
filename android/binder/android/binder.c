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

		Linuxϵͳ�н��̼�ͨ�ŵķ�ʽ��:socket, named pipe,message queque, signal,share memory��Javaϵͳ�еĽ��̼�ͨ�ŷ�ʽ
	��socket, named pipe�ȣ�androidӦ�ó���������Ȼ����Ӧ��JAVA��IPC����ʵ�ֽ��̼��ͨ�ţ����Ҳ鿴android��
	Դ�룬��ͬһ�ն��ϵ�Ӧ�������ͨ�ż�����������ЩIPCͨ�ŷ�ʽ��ȡ����֮����Binderͨ�š�GoogleΪ
	ʲôҪ�������ַ�ʽ�أ���ȡ����Binderͨ�ŷ�ʽ�ĸ�Ч�ʡ� Binderͨ����ͨ��linux��binder driver��ʵ�ֵģ�
	Binderͨ�Ų��������߳�Ǩ��(thread migration)���������̼�IPC������������һ�����̽�����һ������ִ�д�
	��Ȼ�����ִ�еĽ�����ء�Binder���û��ռ�Ϊÿһ������ά����һ�����õ��̳߳أ��̳߳����ڴ�
	������IPC�Լ�ִ�н��̱�����Ϣ��Binderͨ����ͬ���������첽��
	
    		Android�е�Binderͨ���ǻ���Service��Client�ģ�������ҪIBinderͨ�ŵĽ��̶����봴��һ��IBinder�ӿڣ�ϵͳ��
    	��һ�����̹������е�system service,Android�������û���ӷ���Ȩ��System service,��Ȼ����Դ�뿪���ˣ�����
    	�����޸�һЩ������ʵ����ӵײ�system Service��Ŀ�ġ����û�������˵������ҲҪ����server,����Service��
    	�ڽ��̼�ͨ�ţ�������һ��ActivityManagerService����JAVAӦ�ò����е�service����������(connect),disconnect,���е�
    	ActivityҲ��ͨ�����service�����������صġ�ActivityManagerServiceҲ�Ǽ�����Systems Servcie�еġ�
    	
    		Android���������֮ǰϵͳ��������service Manager���̣�service Manager��binder��������֪ͨbinder kernel��������
    	������̽���ΪSystem Service Manager��Ȼ��ý��̽�����һ��ѭ�����ȴ����������������̵����ݡ��û�
    	����һ��System service��ͨ��defaultServiceManager�õ�һ��Զ��ServiceManager�Ľӿڣ�ͨ������ӿ����ǿ��Ե���
    	addService������System service��ӵ�Service Manager�����У�Ȼ��client����ͨ��getService��ȡ����Ҫ���ӵ�Ŀ��Service��
    	IBinder�������IBinder��Service��BBinder��binder kernel��һ���ο�������service IBinder ��binder kernel�в��������ͬ��
    	����IBinder����ÿһ��Client����ͬ����Ҫ��Binder�������򡣶��û�������ԣ����ǻ���������Ϳ�
    	��ͨ��binder kernel����service�����еķ�����Client��Service�ڲ�ͬ�Ľ����У�ͨ�����ַ�ʽʵ���������̼߳�
    	��Ǩ�Ƶ�ͨ�ŷ�ʽ�����û�������Ե�����Service���ص�IBinder�ӿں󣬷���Service�еķ�������ͬ������
    	���ĺ�����(  �˶μ�Service_manager.c �Ĵ��������Ŀ¼Ϊandroid\source\frameworks\base\cmds\servicemanager )

    	���ȴ�ServiceManager ע��������𲽷����������������ʵ�ֵġ���android\source\frameworks\base\cmds\servicemanager\Service_manager.c ��main ������ʼ

*/



/*=======================================================
��������

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

static struct dentry *binder_debugfs_dir_entry_root; /* ������binder_init �еĲ�������ֵ������binder ��Ŀ¼��*/
static struct dentry *binder_debugfs_dir_entry_proc; /* ������binder_init �еĲ�������ֵ������proc �ļ�ϵͳ�е�binder Ŀ¼�Ӧ����/proc/binder/ */
static struct binder_node *binder_context_mgr_node; /* Service Manager ����ʹ�õ�node �ṹ*/
static uid_t binder_context_mgr_uid = -1; /* ���ڱ���Service Manager ���̵�id */
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


static struct binder_transaction_log binder_transaction_log; 		/* �����ݽṹbinder_transaction_log �Ķ���*/
static struct binder_transaction_log binder_transaction_log_failed;

static struct binder_transaction_log_entry *binder_transaction_log_add(struct binder_transaction_log *log)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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

struct binder_node /* binder ��������ʵ��*/
{
	int debug_id;
	struct binder_work work;
	
	union 
	{
		struct rb_node rb_node;
		struct hlist_node dead_node;
	};
	
	struct binder_proc *proc; /* ������binder_new_node ������еĸ�ֵ��ʵ�ʸ���ֵΪbinder_open  �з�����ڴ�*/
	struct hlist_head refs;
	
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	void __user *ptr; /* binder ����ı��ص�ַ*/
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
	uint32_t desc; /* binder �����Զ�������������Service Manager ��node ��ֵΪ0��������node ��ֵΪ����0 �ģ���ֵ��Ӧ��handle ��������binder_get_ref_for_node �еĴ���*/
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
	struct rb_root threads; /* �˽��̵������̺߳�����ĸ���������ش���(binder_get_thread) �ķ����ɳ����жϽڵ����ݽṹbinder_thread ��ͨ�����Աrb_node ���뵽�˺������ʱ����binder_thread �����Աpid Ϊ˳���*/
	struct rb_root nodes;	/* �ڵ������ĸ���������ش���(binder_new_node) �ķ����ɳ����жϽڵ����ݽṹbinder_node ��ͨ�����Աrb_node ���뵽�˺������ʱ����binder_node �����Աptr Ϊ˳���*/
	struct rb_root refs_by_desc;/* ������ĸ���������ش���(binder_get_ref_for_node) �ķ����ɳ����ж����ݽṹbinder_ref ��ͨ�����Աrb_node_desc ���뵽�˺������ʱ����binder_ref �����Աdesc Ϊ˳���*/
	struct rb_root refs_by_node;/* ������ĸ���������ش���(binder_get_ref_for_node) �ķ����ɳ����ж����ݽṹbinder_ref ��ͨ�����Աrb_node_node ���뵽�˺������ʱ����binder_ref �����Աnode Ϊ˳���*/

	int pid; /* �ں���binder_open �б���ֵΪcurrent->group_leader->pid�����߳��鳤��pid */
	
	struct vm_area_struct *vma; /* ������binder_mmap ������еĸ�ֵ*/
	struct task_struct *tsk; /* ������binder_open ������еĸ�ֵ��ָ�����binder_open  ���̵߳�task struct  ���ݽṹ*/
	struct files_struct *files; /* ������binder_mmap ������еĸ�ֵ*/
	
	struct hlist_node deferred_work_node;
	int deferred_work;
	void *buffer;
	/*
		�û���Ҫӳ���������ʼ��ַΪvma->vm_start�����������ַΪvma->vm_end������������
		get_vm_area �ĵ��ú��õ���������ʼ��ַΪarea->addr�������linux �ں�ѧϰ�ʼ��жԴ�
		�����ķ���( �����������ú���get_vm_area ֻ�Ǵ�����Ҫ���������ռ�Ĵ�С������
		�����ڲ��ͻ��������ռ�Ĵ�С��ȫ�������ַ���ݽṹ�������ҵ����ʵĵط�
		��Ȼ�����һ���������ݽṹ�������������е����������ַ�������ȷ����������
		�ṹ�е���ʼ��ַ����area->addr) ������ӳ��������ַ�ͷ�������ʼ��ַ��
		��vma->vm_start ��area->addr �����һ����ƫ�����proc->user_buffer_offset �������ڱ����ֵ��
	*/
	ptrdiff_t user_buffer_offset; /* ������binder_mmap �еķ�������ֵ*/

	struct list_head buffers; /* */
	/* 
		free ��alloced �ֱ�������������������buffer �ռ�ģ��൱�����е�buffer �ռ䶼
		�Ǵ����Ѿ�����õģ�ֻ����free ��alloced ���������֮�����ת������ôbuffer ��
		�������������أ������ں���binder_mmap �н��е�
		
		���һ��binder_buffer ��ִ���ͷŶ��������alloced ����ɾ�������뵽free ����
		���һ��binder_buffer ��ִ�з��䶯�������free ����ɾ�������뵽alloced ����
	*/
	struct rb_root free_buffers; /* ������ĸ���������ش���(binder_insert_free_buffer) �ķ����ɳ����ж����ݽṹbinder_buffer ��ͨ�����Աrb_node ���뵽�˺������ʱ����binder_buffer �д���buffer �Ĵ�СΪ˳���*/
	struct rb_root allocated_buffers; /* ������ĸ���������ش���(binder_insert_allocated_buffer) �ķ����ɳ����ж����ݽṹbinder_buffer ��ͨ�����Աrb_node ���뵽�˺������ʱ����binder_buffer ����ĵ�ַΪ˳���*/
	size_t free_async_space;

	struct page **pages; 	/* 	��Ϊһ��ָ�����飬��������ڴ�����ں���binder_mmap ��ʵ�ֵġ�
							������binder_update_page_range �еĴ����������Ϊһ��ָ�����飬�����е�
							ÿ����Ԫ��ָ��һ��ʵ�ʵ�����ҳ�棬��ÿ����Ԫ��ָ��һ����
							��������buffer �����һ������ҳ��
						*/
	size_t buffer_size;
	uint32_t buffer_free;
	struct list_head todo;
	wait_queue_head_t wait;
	struct binder_stats stats;
	struct list_head delivered_death;
	int max_threads;	/* ������binder_ioctl �е�BINDER_SET_MAX_THREADS ������õĸ�ֵ�������趨�̳߳ص�����*/
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
	int pid; /* �ں���binder_get_thread �б���ֵΪcurrent->pid�����ú������Ǹ��̵߳�pid�������߳��鳤��pid (proc->pid) */
	int looper;
	struct binder_transaction *transaction_stack; /* transaction ��һ����ջ���൱�ڷ��͸���������Ҫ����Ķ��������������*/
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1�����ز���buffer �е�buffer �ռ�Ĵ�С
		2��ͼʾ˵��

			-----------------------------------------------------------------------------------------------------------------------------
			|binder_buffer �ṹ1	|XXXXXXXXXXXXXXXXXXXXXXXX|binder_buffer �ṹ2|XXXXXXXXXXXXXX|binder_buffer �ṹ3|XXXXXXXXXXXXXXXX|
			-----------------------------------------------------------------------------------------------------------------------------
			|																															|
			|																															|
			|																															|
			start																															end
			

			ͼʾΪһ�������ĵ�ַ�ռ��ڵ��������ݣ�����XXXXX Ϊ���ݿռ䣬��start ��end Ϊ����
			binder_mmap �д��������û�ӳ�����ʼ�ͽ�����ַ������ͨ��binder_mmap �Ĵ����֪
				proc -> buffer  		= start;
				proc -> buffer_size	= end;
			
			ͼʾ�ɼ���������ַ�ռ��������ɶ��binder_buffer �ṹ������ģ����е�binder_buffer �ṹ
			��һ������������( ��proc �����Աbuffers ����������)����˻��һ��binder_buffer ��buffer ��
			С���ǻ�ȡ���������XXXXX  �ռ�Ĵ�С

			
			binder_buffer ���ݽṹ�е����һ�����Աdata[0]������ binder_buffer ->data Ϊһ����ֵַ������
			�������XXXX �ռ����ʼ��ַ��

			�������ķ������֪�˺����Ļ�ȡԭ���ˣ����������
			
			1�������buffer Ϊ�����ռ������һ��binder_buffer ���ݽṹ
				size 	= end - buffer->data 
					= (proc->buffer + proc->buffer_size) - (buffer->data)
					
			2�������buffer ���������ռ������һ��binder_buffer ���ݽṹ
				size	= ( ��һ��binder_buffer �ṹ����ʼ��ַ) - ( ����binder_buffer ���ݽṹ��������ʼ��ַ)
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
	����:
		1��proc			: ������open ����������ڴ����ݽṹ
		2��new_buffer	: ����һ��binder_buffer �ĵ�ַָ��
		
	����:
		1��
		
	˵��:
		1���˺�����ִ�й���
			A��������proc �����Աfree_buffers Ϊ���ĺ�����в��ң�ȷ������
				�Ĳ���Ӧ�ò����λ��( ��binder_buffer ���������buffer ��СΪ˳�����)
			B��������Ĳ���new_buffer ��ָ���binder_buffer ���뵽proc �����Ա
				free_buffers Ϊ���ĺ������
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
	����:
		1��proc			: ������open ����������ڴ����ݽṹ
		2��new_buffer	: ����һ��binder_buffer �ĵ�ַָ��
		
	����:
		1��
		
	˵��:
		1���˺�����ִ�й���
			A��������proc �����Աallocated_buffers Ϊ���ĺ�����в��ң�ȷ������
				�Ĳ���Ӧ�ò����λ��( ��binder_buffer ����ĵ�ַΪ˳����룬�ο�binder_buffer_size ����˵��)
			B��������Ĳ���new_buffer ��ָ���binder_buffer ���뵽proc �����Ա
				allocated_buffers Ϊ���ĺ������
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
	
	rb_link_node(&new_buffer->rb_node, parent, p);/* ���뵽�������*/
	rb_insert_color(&new_buffer->rb_node, &proc->allocated_buffers);/* ���º�����иղ���ڵ����ɫ*/
}

static struct binder_buffer *binder_buffer_lookup(struct binder_proc *proc, void __user *user_ptr)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��������binder_buffer_size �е�˵����֪��������û�user_ptr  ָ��ʵ�ʾ���XXXX �ռ�ĵ�ַ��ת�����
			�û���ֵ������proc �����Աallocated_buffers ��ά�����ѷ���buffer �ĺ��������binder_buffer ���ݽṹ��
			��ʼ��ַ������ģ�������Ҫ�������user_ptr ��ַת��Ϊ��Ӧ��binder_buffer ���ݽṹ����ʼ��ַ
			(  �ο�binder_buffer_size ����˵��)
			
		2���˺�����ִ�й���
			A��������proc �����Աallocated_buffers Ϊ���ĺ�����в��������user_ptr ����������� ƥ���
				buffer������ҵ��ͷ��ش�buffer
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
	����:
		1��proc		: ������open ����������ڴ����ݽṹ
		2��allocate	: �����Ƿ�Ϊ�����־�����Ϊ0 ��ʾҪ�ͷſռ估�Ͽ�ҳʽӳ�䣬1 ��Ϊ����ʵ�ʵĿռ䲢����ҳʽӳ��
		3��start		: ������ʼ��ַ(  ���ַ����ֵΪ����get_vm_area ����ִ�з��ص�vm_struct -> addr ��ֵ����ֵ���û��ĵ�ַ����һ����ƫ���proc �����Աuser_buffer_offset ��˵��)
		4��end		: ���������ַ(  ��start ��˵����������)
		5��vma		: ����һ��vm_area_struct ���ݽṹ�������ֵΪ�վͻ�ʹ�õ���binder_mmap ʱ�����vma ���ݽṹ��������
		
	����:
		1��
		
	˵��:
		1���˺����ڲ�������ʵ����Ϊ��ʼ��ַ��������ַ֮������ַ�����ڴ�ռ䣬��
			����ʵ��ҳ��ӳ��Ĺ��̡�
		2��������ִ�й���:
			A���Դ���Ĳ�������У��( ������ַ�Ƿ�����ʼ��ַ֮��)
			B��������ʼ��ַ��������ַ����ʵ�ʵ��ڴ���䣬��������õ���ÿ���ڴ�
				ҳ���ַ���浽proc ���ݽṹ��pages ���Ա��������
				���������������ڴ�ʱ�ǰ���ҳΪ��λ��С������
			C����ÿ�����������ҳ�����ҳʽӳ��Ȳ���
			D��ͬʱ�������û���vm ���ݽṹ�еĵ�ַ��Ϣ
*/
	void *page_addr;
	unsigned long user_page_addr;
	struct vm_struct tmp_area;
	struct page **page;
	struct mm_struct *mm;

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: %s pages %p-%p\n", proc->pid, allocate ? "allocate" : "free", start, end);

	if (end <= start) /* ����У��*/
		return 0;

	if (vma)
		mm = NULL;
	else
		mm = get_task_mm(proc->tsk);

	if (mm)
	{
		down_write(&mm->mmap_sem);
		vma = proc->vma; /* ȡ������binder_mmap �д����vma ���ݽṹ*/
	}

	if (allocate == 0) /* �ͷſռ�*/
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
			��ȡһ��proc �����Աpages �������е�һ��Ԫ��( ���ڱ���ʵ�ʵ�����ҳ���ַ)
		*/
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];

		BUG_ON(*page);
		
		/* 
			���������������ڴ�ռ䣬��������õ�������ҳ���
			ַ���浽proc �����Աpages ��������
		*/
		*page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (*page == NULL) 
		{
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed ""for page at %p\n", proc->pid, page_addr);
			goto err_alloc_page_failed;
		}
		
		tmp_area.addr = page_addr;

		/* 
			��linux ѧϰ�ʼ��п�֪������map_vm_area �л����ȶ�tmp_area->size ��ִֵ�м�ȥһ
			��PAGE_SIZE �Ĳ��������������ַ�ģ����Դ˴���Ҫ����һ��PAGE_SIZE ��ֵ
		*/
		tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */; 
		page_array_ptr = page;

		/*
			������ոշ��������ҳ�����ҳʽӳ��Ȳ���
			���������ҳ���ַ�������ַ����ӳ��
		*/
		ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
		if (ret) 
		{
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed " "to map page at %p in kernel\n", proc->pid, page_addr);
			goto err_map_kernel_failed;
		}

		/* ��õ��û���ҳ����ʼ��ַ*/
		user_page_addr = (uintptr_t)page_addr + proc->user_buffer_offset;

		/* ��������ĵ�ַ��������ҳʽӳ�����ת��Ϊ�û��ĵ�ַ���뵽vma ���ݽṹ��*/
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
	����:
		1��proc			: ������open ����������ڴ����ݽṹ
		2��data_size		: ����data �Ĵ�С
		3��offsets_size	: ����offset �Ĵ�С
		4��is_async		: 
		
	����:
		1��
		
	˵��:
		1��˵��(  ��ý��binder_buffer_size ������˵��)
		
			����ǰ�ռ�ʾ��ͼ:
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|binder_buffer �ṹ1	|XXXXXX|binder_buffer �ṹ2|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |binder_buffer �ṹ3|XXXXX|binder_buffer �ṹ4|XXXX|
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|												|									  							|													|
					|												|									  							|													|
					|												xxx									  							yyy													|
					start																																									end

			����: 
					xxx ~~ yyy �Ŀռ�û�н�������ҳ��ķ��䣬��û�н���
					ҳ��ӳ�䣬�����ڽṹ2 �����Ա��free=0
					
					binder_buffer �ṹ1 ��XXXX �ռ��СΪ1K;
					binder_buffer �ṹ2 ��XXXX �ռ��СΪ4K;
					binder_buffer �ṹ3 ��XXXX �ռ��СΪ2K;
					binder_buffer �ṹ4 ��XXXX �ռ��СΪ5K;

			����:
					�û���Ҫ����Ŀռ��СΪ(data_size+offsets_size) 3K

			����:
					����binder_buffer �ĺ���������ҵ����ʺϵ�Ӧ����binder_buffer �ṹ2 

			����:
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|binder_buffer �ṹ1	|XXXXXX|binder_buffer �ṹ2|XXXXXXXXXXXXXXXXXXXX |binder_buffer �ṹ5|XXXXXXXXXXXXXXXX |binder_buffer �ṹ3|XXXXX|binder_buffer �ṹ4|XXXX|
					--------------------------------------------------------------------------------------------------------------------------------------------------------------------
					|												|						 |	   				|		     			|													|
					|												|						 |	   				|		     			|													|
					|												xxx						 aa	   				bb		      			yyy													|
					start																																									end

			���:
					�����о����Կ���buffer  �Ĳ��ң�����ҵ��ṹ2 ������Ŀռ��ʺϷ����û�����
					�ṹ2 ����Ŀռ��ִ����û���Ҫ��( û�����õ�)�����Խ��ṹ2 ����Ŀռ����
					��ַ��䣬��������ʵ���˽�aa ~~ cc �Ŀռ�����������ڴ�ķ��䲢����ҳ��ӳ
					�䣬xxx ~~ aa �Ŀռ�Ϊ3k �����÷�����û����ɽṹ2 �������˺������ؽṹ2
					�ĵ�ַ��aa ~~ bb Ϊһ��binder_buffer ���ݽṹ�Ŀռ䣬���ṹ5 ���ڴ�ռ䣬����˿�
					���Ŀ�ľ���Ϊ�˶Բ�ֺ��bb ~~ yyy ��һ�ε�ַ���й��������Ϊԭ��������
					xxx ~~ yyy �Ŀռ䶼���нṹ2 ������ģ����ھ������֮��ṹ2 ֻ������xxx ~~ aaa
					�Ŀռ䣬��ôʣ�µĿռ���ô�죬���Ծ���ʣ�µĿռ��з�����һ���ṹ5��Ȼ
					���ýṹ5 ��bb ~~ yyy ���й�������������������ڴ�ռ�Ϊxxx ~~ bb

					( �����ķ������û�����Ŀռ�Ϊ3k��û�����õ�buffer ���ã�����û����������
					��4k �Ŀռ䣬��ṹ2 ������Ŀռ����ã���ô��ֱ�Ӷ�xxx ~~ yyy �ĵ�ַ��������
					ҳ��ķ��估ҳʽӳ��Ϳ����ˣ�Ȼ�󷵻ؽṹ2 �ĵ�ַ)

					���������������˺�������ʵ�ֵ��ڴ���估ҳʽӳ��Ŀռ�Ϊxxx ~~ bb
					
					binder_buffer �ṹ1 ��XXXX �ռ��СΪ1K;
					binder_buffer �ṹ2 ��XXXX �ռ��СΪ3K [xxx~~aa];  // --- ������û�ʹ����
					binder_buffer �ṹ5 ��XXXX �ռ��СΪ1K-sizeof(struct binder_buffer) [bb~~yyy];
					binder_buffer �ṹ3 ��XXXX �ռ��СΪ2K;
					binder_buffer �ṹ4 ��XXXX �ռ��СΪ5K;
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

	/* ����data ��offset ����size ���ܺ�*/
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

	/* �����ܹ���Ҫ����Ŀռ��С�ڿ��к�������ҵ����ʵ�buffer �ṹ*/
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
		ע�������ѭ��	
			����ҵ�size == buffer_size ��buffer �Ļ�����n != NULL;
			���û�ҵ�size == buffer_size ��buffer �Ļ�����size < buffer_size����n = NULL;
	*/
	
	if (best_fit == NULL) 
	{
		printk(KERN_ERR "binder: %d: binder_alloc_buf size %zd failed, " "no address space\n", proc->pid, size);
		return NULL;
	}
	
	if (n == NULL)  /* n==NULL ��ʾһ�����ҵ���һ��size < buffer_size ��buffer */
	{
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		buffer_size = binder_buffer_size(proc, buffer);
	}

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_alloc_buf size %zd got buff" "er %p size %zd\n", proc->pid, size, buffer, buffer_size);

	has_page_addr = (void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
	if (n == NULL) /* n==NULL ��ʾһ�����ҵ���һ��size < buffer_size ��buffer */
	{
		/* 
			��������Ҫ���������ҳ��Ŀռ��С�����û�Ҫ����Ĵ�
			С����һ��binder_buffer �ṹ�Ĵ�С��������˵��
		*/
		if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
			buffer_size = size; /* no room for other buffers */
		else
			buffer_size = size + sizeof(struct binder_buffer);
	}
	
	end_page_addr = (void *)PAGE_ALIGN((uintptr_t)buffer->data + buffer_size);
	
	if (end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;

	/* ���ҵ���buffer ���ݽṹ�е���ʼ��ַ��������ַ֮��������ַ����ʵ�ʵ��ڴ�ҳ����䣬��������Ӧ��ҳʽӳ��*/
	if (binder_update_page_range(proc, 1, (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr, NULL))
		return NULL;

	rb_erase(best_fit, &proc->free_buffers);
	buffer->free = 0;
	/* ���շ����buffer ���뵽�ѷ����buffer �������*/
	binder_insert_allocated_buffer(proc, buffer); /* �������ڲ�*/

	/* 
		����ҵ���buffer ������Ŀռ��С����Ҫ����Ŀռ��С����ȣ���˵
		��ԭ�еĿռ����Ҫ�Ŀռ�С����˽�ʣ��Ĳ��������½��й���

		��˵����binder_buffer �ṹ5 �����ɣ����binder_buffer �ṹ2 �Ŀռ����������û�
		����Ĵ�С���Ͳ�����binder_buffer �ṹ5 �Ĳ���
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��ִ�й���:
			A�����Ƚ��������buffer ��proc �����Աallocated_buffers ������ĺ������ɾ��
			B�����ͷź��buffer ���뵽proc �����Աfree_buffers ������ĺ������
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1���˺���ʵ���˸��ݲ���ptr ��proc �����Աnodes ������ĺ����
			�в��ң�����ҵ��ͷ��أ����򷵻ؿ�
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1���������߲���һ��binder  ��ʵ��
		2���˺�����ִ�й���
			A��������proc �����Աnodes Ϊ���ĺ�����в��������ptr ƥ���
				�ڵ㣬����ҵ��ͷ��ش˽ڵ�
			B������A  ����û�ҵ������ʱ����һ���ڵ���ڴ�ռ䣬ͬʱ��
				�·���Ľڵ������Ӧ�ĳ�ʼ������ͨ���ڵ��е�rb_node ���Ա
				���˽ڵ���뵽proc �����Աnodes Ϊ���ĺ������
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
	
	rb_link_node(&node->rb_node, parent, p); /* ͨ���ڵ��е�rb_node ���Ա�������뵽proc ��nodes ���Ա�ĺ������*/
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1���˺���ʵ���˸��ݲ���desc ��proc �����Աrefs_by_desc ������ĺ����
			�в��ң�����ҵ��ͷ��أ����򷵻ؿ�
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1���˺���ʵ�ֵĹ����Ǹ���node ����ref������˵��һ��ref ������proc �ĵط�������
			�����пɿ�����ref  ��proc �ṹ�д���������������У�ͬʱ�������������У�
			�ֱ�Ϊ:
				��1  ������refs_by_node �������
				��2  ������refs_by_desc  �������
			
			���ҵ�ԭ���Ǹ��ݴ����node �ڵ�1  ��(refs_by_node) ������в��ң������������
			A���ҵ���
				ֱ�ӷ����ҵ���ref
			B��û�ҵ�
				���·���һ��ref  ���ڴ�ռ䣬������Ĳ���node ��ֵ���·����ref �����Ա��
				Ȼ���µ�ref  ���뵽��1  ��������С�
				�ٱ�����2  ��������е����г�Ա��Ȼ��Ϊ�·����ref ����һ��Ŀ��ֵ����
				desc  ֵ��Ȼ���ٽ��µ�ref  ���뵽��2  ���������
			
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��proc 		: ������open ����������ڴ����ݽṹ
		2��thread 		: ����thread ���ݽṹ
		3��tr 			: ����binder_transaction_data ���ݽṹ
		4��reply 		: �����Ƿ�ΪӦ��0 ��Ӧ��
		
	����:
		1��
		
	˵��:
		1��
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
	e->from_proc = proc->pid; /* ȡ��proc ��Ӧ���߳��鳤��pid */
	e->from_thread = thread->pid; /* ȡ�������̵߳�pid */
	e->target_handle = tr->target.handle; /* ȡ��Զ��binder ���������ֵ*/
	e->data_size = tr->data_size;
	e->offsets_size = tr->offsets_size;

	if (reply) /* ΪӦ��*/
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
	else /* Ϊ��Ӧ��*/
	{
		if (tr->target.handle) /* �����ֵ��Ϊ0�����ʾΪԶ�˵�����������Ҫ���ݴ������ҵ���ref �ṹ*/
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
		else /* ������д��server ��*/
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
			������ǵ��򴫵ݣ����ұ������յ�����Ҫ����Ķ�ջ��Ϊ�գ������
			�յ�����Ϣ����ȡ�Է�����Ϣ
		*/
		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) 
		{
			struct binder_transaction *tmp;
			tmp = thread->transaction_stack;
			if (tmp->to_thread != thread) /* �����ջ�е���Ϣ���Ƿ��͸����̵߳ģ�һ���ǳ�����*/
			{
				binder_user_error("binder: %d:%d got new ""transaction with bad transaction stack"", transaction %d has target %d:%d\n",proc->pid, thread->pid, tmp->debug_id,tmp->to_proc ? tmp->to_proc->pid : 0,tmp->to_thread ?tmp->to_thread->pid : 0);
				return_error = BR_FAILED_REPLY;
				goto err_bad_call_stack;
			}
			
			while (tmp) 
			{
				if (tmp->from && tmp->from->proc == target_proc)
					target_thread = tmp->from;/* ȡ����ջ��ĳ����Ϣ�����ĸ��̵߳�*/
				
				tmp = tmp->from_parent;
			}
		}
	}
	
	if (target_thread) /* �ҵ�Ŀ���߳�*/
	{
		e->to_thread = target_thread->pid;
		target_list = &target_thread->todo;
		target_wait = &target_thread->wait; 
	} 
	else /* û�ҵ�Ŀ���̣߳����proc �б����Ŀ���߳��鳤��ΪĿ�꣬������*/
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
	/* ��Ŀ�Ľ��̻��̵߳�proc ���ݽṹ�������ڴ����*/
	t->buffer = binder_alloc_buf(target_proc, tr->data_size,tr->offsets_size, !reply && (t->flags & TF_ONE_WAY)); /* �������ڲ���ʵ�ַ���buffer �������뵽proc ��allocated_buffers �������*/
	
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

		�������ķ�����֪�����е�����ֵ:
		tr->offsets_size 		= addr3 - addr2
		tr->data.ptr.offsets	= addr2
		tr->data_size 			= addr2 - addr1
		t->buffer->data 		= addr1
	*/
	
	if (target_node)
		binder_inc_node(target_node, 1, 0, NULL);

	offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));

	/* ���û��ռ�����ݿ�������*/
	if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) 
	{
		binder_user_error("binder: %d:%d got transaction with invalid ""data ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}

	/* ���û��ռ��offset ���ݿ�������*/
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

	/* ����offset ����*/
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
			/* ���ض���*/
			case BINDER_TYPE_BINDER:
			case BINDER_TYPE_WEAK_BINDER: 
				{
					struct binder_ref *ref;

					/*
						���ڱ��ص�proc �ṹ�и��ݴ������Ϣ������node �ṹ������ҵ���ok�����
						û�ҵ��Ǿ��ڱ���proc �ṹ�з���һ��node �ṹ�������������Ӧ�ĸ�ֵ
					*/
					struct binder_node *node = binder_get_node(proc, fp->binder);

					/* ��õ�����proc �еĽڵ�*/
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
						����ִ�е��˴�ʱ���ص�node  �ṹһ���Ѿ������ˣ�������Ҫ�������
						node �Ľṹ����Ŀ��proc �Ľṹ���ҵ�һ��ָ���node ��ref�����Ŀ��proc
						�ṹ��û��������ref ��ô����Ŀ��proc �з���һ��ref������ref ָ���node
					*/

					/* ���Ŀ��proc �е�ref  (  ע�������ñ��ص�node ��ȡĿ��proc ��ref ��������binder_get_ref_for_node ˵������Ŀ�Ķ�����ref �����ã���ref ��node Ϊ���ص�)*/
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

			/* Զ�̶��������*/
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

	/* ����Ŀ���̻߳����*/
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
	����:
		1��proc 		: ������open ����������ڴ����ݽṹ���������ļ����ݽṹ��˽�����У��� filp->private_data
		2��thread 		: ����thread ���ݽṹ
		3��buffer 		: �����д��������buffer��Ϊ�û��ռ�ĵ�ַ�����û��ռ�Ҫͨ��binder ����д����ʱ�Ĵ�д������������
		4��size 			: �����д������buffer �ĳ���
		5��consumed 	: ����ʱΪ��buffer ��ʲô�ط���ʼΪ��Ч�����ݣ�����ʱΪ��buffer ����ʼ��ַ���Ѿ�д������ݵ�ַ֮��ĳ���
		
	����:
		1��
		
	˵��:
		1��
*/
	uint32_t cmd;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

/*
	��������buffer �е����ݸ�ʽ:
		while(ptr < end && thread->return_error == BR_OK)
		{
			cmd : 4 ���ֽ�

			���������ݸ���cmd �Ĳ�ͬ�����ж��壬������
		}
*/

	while (ptr < end && thread->return_error == BR_OK) 
	{

		/* ===1====> cmd : 4 ���ֽ�	*/
		if (get_user(cmd, (uint32_t __user *)ptr)) /* ���û��ռ��е�buffer �����ȶ�ȡһ��32 λ�����ݣ���ֵΪ��Ӧ������*/
			return -EFAULT;

		ptr += sizeof(uint32_t);
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) 
		{
			binder_stats.bc[_IOC_NR(cmd)]++;
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}

		/*
			����Щ�����У���õ���BC_TRANSACTION/BC_REPLY����ԣ�Binder����ͨ���������͸����շ�����
			�����������ص��� �ݰ��ɽṹ��struct binder_transaction_data���塣Binder������ͬ�����첽֮�֣���
			��binder_transaction_data�� flag�����֡����flag���TF_ONE_WAYλΪ1��Ϊ�첽��������Client�˷��������󽻻�
			�������� Server�˲��ٷ���BC_REPLY���ݰ�������Server�᷵��BC_REPLY���ݰ���Client�˱���ȴ��������
			���ݰ��������һ�ν�����
		*/
		
		switch (cmd) 
		{
			case BC_INCREFS:
			case BC_ACQUIRE:
			case BC_RELEASE:
			case BC_DECREFS: 
				{
					/*
						����:
							�����������ӻ����binder�����ü���������ʵ��ǿָ�����ָ��Ĺ��ܡ�
						����:
							32λbinder���ú�
					*/
					uint32_t target;
					struct binder_ref *ref;
					const char *debug_string;

					/* ===2====> target : 4 ���ֽ�	*/
					if (get_user(target, (uint32_t __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(uint32_t);

					/* 
						��Ϊ��д���ݺ���������Ҫ������д�뵽�ĸ�binder ����( �൱���ĸ����̻��߳�) ����ͨ��
						Զ�̵�������ȷ���ġ������ͨ��target ��Զ�������ҵ�ref ���ݽṹ
					*/
					if (target == 0 && binder_context_mgr_node && (cmd == BC_INCREFS || cmd == BC_ACQUIRE))
					{
						ref = binder_get_ref_for_node(proc, binder_context_mgr_node);/* �������ڲ�*/
						if (ref->desc != target) 
						{
							binder_user_error("binder: %d:""%d tried to acquire ""reference to desc 0, ""got %d instead\n",proc->pid, thread->pid,ref->desc);
						}
					} 
					else
						ref = binder_get_ref(proc, target);/* �������ڲ�*/
					
					if (ref == NULL) 
					{
						binder_user_error("binder: %d:%d refcou""nt change on invalid ref %d\n",proc->pid, thread->pid, target);
						break;
					}

					/* ����ִ�е��˴�һ�����ҵ���һ��binder_ref ���ݽṹ*/
					
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
						����:
							��һ������binderʵ��Ӧ�ü���ʱ��������binderʵ�����ڵĽ��̷���BR_INCREFS, BR_ACQUIRE��Ϣ��binder
							ʵ�����ڵĽ��̴�����ϻ���BR_INCREFS_DONE, BR_ACQUIRE_DONE
						����:
							void * ptr;  		binderʵ�����û��ռ��е�ָ��
							void* cookie; 		���ʵ����صĸ�������
					*/
					void __user *node_ptr;
					void *cookie;
					struct binder_node *node;

					/* ===2====> node_ptr : 4 ���ֽ�	*/
					if (get_user(node_ptr, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);

					/* ===3====> cookie : 4 ���ֽ�	*/
					if (get_user(cookie, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);
					node = binder_get_node(proc, node_ptr); /* �������ڲ�*/
					
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
						����:
							�ͷ�һ��ӳ����ڴ档binder���շ�ͨ��mmap()ӳ��һ��ϴ���ڴ�ռ䣬binder����������Ƭ
							�ڴ�������ƥ���㷨ʵ�ֽ������ݻ���Ķ�̬������ͷţ����㲢������Խ��ջ���
							������Ӧ�ó���������Ƭ���ݺ���뾡��ʹ�ø������ͷŻ��������������Ϊ����
							���ľ����޷�����������
						����:
							ָ����Ҫ�ͷŵĻ�������ָ�룻��ָ��λ���յ���binder���ݰ���
					*/
					void __user *data_ptr;
					struct binder_buffer *buffer;

					/* ===2====> data_ptr : 4 ���ֽ�	*/
					if (get_user(data_ptr, (void * __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(void *);

					buffer = binder_buffer_lookup(proc, data_ptr); /* �������ڲ�*/
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

			case BC_TRANSACTION:	/* д����������*/
			case BC_REPLY: /* д��ظ�����*/
				{
					struct binder_transaction_data tr;

					/* ===2====> data_ptr : sizeof(tr) ���ֽ�	*/
					if (copy_from_user(&tr, ptr, sizeof(tr)))
						return -EFAULT;

					/*
						�����transaction �����д������ݿ�ʼ�Ĳ���һ����һ��binder_transaction_data ���͵����ݽṹ
						��������ȡ��������ݽṹ��Ȼ�����binder_transaction ����ִ�У�������binder_transaction 
					*/
					
					ptr += sizeof(tr);
					binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
					break;
				}

			case BC_REGISTER_LOOPER:
				/*
					����:
						������ͬBINDER_SET_MAX_THREADSһ��ʵ��binder�����Խ��շ��̳߳ع���BC_REGISTER_LOOPER֪ͨ����
						�̳߳���һ���߳��Ѿ������ˣ�BC_ENTER_LOOPER֪ͨ�����߳��Ѿ�������ѭ�������Խ������ݣ�
						BC_EXIT_LOOPER֪ͨ�����߳��˳���ѭ�������ٽ�������
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
				
				thread->looper |= BINDER_LOOPER_STATE_REGISTERED; /* ������sevice manager  �̵߳�ע����*/
				break;
				
			case BC_ENTER_LOOPER:
				/*
					����:
						������ͬBINDER_SET_MAX_THREADSһ��ʵ��binder�����Խ��շ��̳߳ع���BC_REGISTER_LOOPER֪ͨ����
						�̳߳���һ���߳��Ѿ������ˣ�BC_ENTER_LOOPER֪ͨ�����߳��Ѿ�������ѭ�������Խ������ݣ�
						BC_EXIT_LOOPER֪ͨ�����߳��˳���ѭ�������ٽ�������
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
					����:
						������ͬBINDER_SET_MAX_THREADSһ��ʵ��binder�����Խ��շ��̳߳ع���BC_REGISTER_LOOPER֪ͨ����
						�̳߳���һ���߳��Ѿ������ˣ�BC_ENTER_LOOPER֪ͨ�����߳��Ѿ�������ѭ�������Խ������ݣ�
						BC_EXIT_LOOPER֪ͨ�����߳��˳���ѭ�������ٽ�������
				*/
				binder_debug(BINDER_DEBUG_THREADS,"binder: %d:%d BC_EXIT_LOOPER\n",proc->pid, thread->pid);
				thread->looper |= BINDER_LOOPER_STATE_EXITED;
				break;

			case BC_REQUEST_DEATH_NOTIFICATION:
			case BC_CLEAR_DEATH_NOTIFICATION: 
				{
					/*
						����:
							���binder���õĽ���ͨ��������Ҫ��������binderʵ�����ٵõ�֪ͨ����˵ǿָ�����ȷ��
							ֻҪ�����þͲ�������ʵ�壬����Ͼ��Ǹ�����̵����ã�˭Ҳ�޷���֤ʵ����������
							��server�ر�binder�������쳣�˳�����ʧ����������������Ҫ��server�ڴ˿̸���֪ͨ
							
						����:
							uint32* ptr; 		��Ҫ�õ�����֪ͨ��binder����
							void** cookie; 	������֪ͨ��ص���Ϣ���������ڷ�������֪ͨʱ���ظ���������Ľ��̡�
					*/
					uint32_t target;
					void __user *cookie;
					struct binder_ref *ref;
					struct binder_ref_death *death;

					/* ===2====> target : 4 ���ֽ�	*/
					if (get_user(target, (uint32_t __user *)ptr))
						return -EFAULT;
					
					ptr += sizeof(uint32_t);

					/* ===3====> cookie : 4 ���ֽ�	*/
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
						����:
							�յ�ʵ������֪ͨ��Ľ�����ɾ��Ӧ�ú��ñ������֪����
							
						����:
							void** cookie; 
					*/
					struct binder_work *w;
					void __user *cookie;
					struct binder_ref_death *death = NULL;

					/* ===2====> cookie : 4 ���ֽ�	*/
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
	����:
		1��proc 		: ������open ����������ڴ����ݽṹ���������ļ����ݽṹ��˽�����У��� filp->private_data
		2��thread 		: ����thread ���ݽṹ
		3��buffer 		: ���뱣���ȡ���ݵ��ڴ�ռ䣬���ڷ��ض�������������
		4��size 			: ���뱣���ȡ���ݿռ�Ĵ�С
		5��consumed 	: ���ڷ��ض�ȡ�������ݳ���( �������ʱ��ֵΪ0  ������buffer  ��д��һ��BR_NOOP  )
		6��non_block	: �Ƿ�����
		
	����:
		1��
		
	˵��:
		1��
*/
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	int ret = 0;
	int wait_for_proc_work;

	if (*consumed == 0) /* ��ֵΪ0��������buffer  ��д��BR_NOOP  */
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
	����:
		1��proc : ������open ����������ڴ����ݽṹ
		
	����:
		1��
		
	˵��:
		1���˺�����ִ�й���
			A��������proc �����Աthreads Ϊ���ĺ�����в����뵱ǰ����pid ƥ���
				�ڵ㣬����ҵ��ͷ��ش˽ڵ�
			B������A  ����û�ҵ������ʱ����һ��binder_thread ���ڴ�ռ䣬ͬʱ��
				�·����binder_thread ������Ӧ�ĳ�ʼ������ͨ��binder_thread �е�rb_node ���Ա
				���˽ڵ���뵽proc �����Աthreads Ϊ���ĺ������
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
		rb_insert_color(&thread->rb_node, &proc->threads); /* ���·����thread ���ݽṹ���뵽proc ��threads ���Ա��*/

		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		thread->return_error = BR_OK;
		thread->return_error2 = BR_OK;
	}
	return thread;
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
	int ret;
	struct binder_proc *proc = filp->private_data; /* ȡ������open ʱ�����binder_proc ���ݽṹ*/
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	/*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/

	/*
		wait_event_interruptible():
			�ú����޸�task ��״̬ΪTASK_INTERRUPTIBLE����ζ�Ÿý��̽������������
			ֱ�������ѣ�Ȼ����ӵ��ȴ�����wq �С���wait_event_interruptible()������
			�ж�condition  �ǲ����Ѿ����㣬�������ֱ�ӷ���0���������__wait_event_interruptible()��
			����__ret����ŷ���ֵ

		ԭ������:
			#define wait_event_interruptible(wq, condition)          \
			({                                                       \
			    int __ret = 0;                                       \
			    if (!(condition))                                    \
			        __wait_event_interruptible(wq, condition, __ret);\
			    __ret;                                               \
			})

		__wait_event_interruptible ԭ������:
			__wait_event_interruptible()���ȶ��岢��ʼ��һ��wait_queue_t����__wait����������Ϊ��ǰ
			����current������__wait��ӡ�������ѭ���У�__wait_event_interruptible()����������Ϊ
			���жϵĹ���״̬���������condition�Ƿ����������������˳����������
			����������ߣ���������󣬼��ѱ���������״̬��Ϊ����̬������__wait ��
			�ȴ���������������Ӷ������ܹ��������С�������̵�ǰ���첽��
			��(POSIX��)���򷵻�-ERESTARTSYS��
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

	/* ������ioctl �Ľ��̹��� caller ������ֱ�� service ����*/
	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2); /* �������������ֱ�ӴӴ˺������أ�����������˯��״̬��������˵��*/
	if (ret)
		return ret;

	mutex_lock(&binder_lock);
	
	thread = binder_get_thread(proc); /* ���ݵ�caller ������Ϣ��ȡ�ý����̳߳����ݽṹ����������˵��*/
	if (thread == NULL) 
	{
		ret = -ENOMEM;
		goto err;
	}

	switch (cmd) 
	{
		/*
			��������õ�������BINDER_WRITE_READ��������Ĳ����������������ݣ�һ��������Binderд��
			�����ݣ�һ������Ҫ�� Binder���������ݣ����������ȴ���д�����ٴ�������֡���������
			�ĺô���Ӧ�ó�����Ժ����ش��������ͬ�����첽��������Ҫ�����첽�������ֻ�� 
			��д���ֶ���read_size�ó�0����Ҫֻ��Binder������ݿ��Խ�д�����ÿռ�write_size�ó�0����Ҫ��
			������ͬ���ȴ��������ݿ� �Խ������ֶ����ϡ�
		*/
		case BINDER_WRITE_READ: 
			{
				struct binder_write_read bwr;
				
				if (size != sizeof(struct binder_write_read)) /* ���㴫����û��ռ����ݵĳ����Ƿ���ȷ������case ���û��ռ䴫���һ��Ҫ��һ��binder_write_read �����ݽṹ�����ݣ�����ʹ���*/
				{ 
					ret = -EINVAL;
					goto err;
				}
				
				if (copy_from_user(&bwr, ubuf, sizeof(bwr))) /* ���û��ռ佫���ݿ������ں˿ռ���*/
				{
					ret = -EFAULT;
					goto err;
				}
				
				binder_debug(BINDER_DEBUG_READ_WRITE,"binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",proc->pid, thread->pid, bwr.write_size, bwr.write_buffer,bwr.read_size, bwr.read_buffer);

				if (bwr.write_size > 0) /* ���Ҫд�����ݳ��ȴ���0���൱��Ҫд�����ݣ����Ե��ú�������д����*/
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
				
				if (bwr.read_size > 0) /* ���Ҫ�������ݳ��ȴ���0���൱��Ҫ�������ݣ����Ե��ú������ж�����*/
				{ 	
					ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
					
					if (!list_empty(&proc->todo))
						wake_up_interruptible(&proc->wait); /* �ָ������caller����*/
					
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
			if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) /* ���û��ռ䴫������ݶ����������*/
			{
				ret = -EINVAL;
				goto err;
			}
			break;
		
		case BINDER_SET_CONTEXT_MGR: /* ���˴򿪵�binder ����Ϊservice ��ֻ������һ������Ϊservice ����android\source\frameworks\base\cmds\servicemanager\Service_manager.c  => main => binder_become_context_manager  �ĵ���*/

			if (binder_context_mgr_node != NULL) /* �ж�serviceMagager  �����Ƿ��Ѿ�������*/
			{
				printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
				ret = -EBUSY;
				goto err;
			}
			
			if (binder_context_mgr_uid != -1) /* �ж�serviceMagager  �����Ƿ��Ѿ�������*/
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
	struct binder_proc *proc = vma->vm_private_data;
	binder_debug(BINDER_DEBUG_OPEN_CLOSE,"binder: %d open vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",proc->pid, vma->vm_start, vma->vm_end,(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,(unsigned long)pgprot_val(vma->vm_page_prot));
	dump_stack();
}

static void binder_vma_close(struct vm_area_struct *vma)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��ִ�й���:
			A����������vma �еĽ�����ַ����ʼ��ַ֮��ķ�Χ����4M �ˣ���ǿ������4M
			B���������ַ���ݽṹ�еı�־�����趨
			C�������proc ( ���̵���binder_open ʱ��õ�) ��buffer ��Ϊ�գ���˵����proc ( �����binder_open �Ľ������Ӧ)
				�Ѿ���ִ�й���ַӳ���ˣ������ù��˺�����
			D��
*/
	int ret;
	struct vm_struct *area;
	struct binder_proc *proc = filp->private_data;
	const char *failure_string;
	struct binder_buffer *buffer;

	if ((vma->vm_end - vma->vm_start) > SZ_4M)/* �ж�4M �߽�*/
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
	
	vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE; /* ��������ռ����ݽṹ�ı�־*/

	if (proc->buffer)/* �жϴ˽����Ƿ��Ѿ����ù��˺������й��ڴ������*/
	{
		ret = -EBUSY;
		failure_string = "already mapped";
		goto err_already_mapped;
	}

	/*
		����get_vm_area �����Ե�ַVMALLOC_START  ��VMALLOC_END  ֮�����һ�����е����Ե�ַ�ռ䡣
		ע��˺���ֻ�Ƿ�����vm_struct ���ݽṹ���ڴ�ռ䣬�����˽ṹ��ӵ���ȫ��vmlist ��
		�����У���û��ʵ�ʷ���������buffer ��ʹ�õ�ҳ��ռ�
		���ں�����get_vm_area ˵���ɼ�linux �ں�ѧϰ�ʼ�
	*/
	area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP); 
	if (area == NULL) 
	{
		ret = -ENOMEM;
		failure_string = "get_vm_area";
		goto err_get_vm_area_failed;
	}

	/*
		�˴��ķ���
		
		�û���Ҫӳ���������ʼ��ַΪvma->vm_start�����������ַΪvma->vm_end������������
		get_vm_area �ĵ��ú��õ���������ʼ��ַΪarea->addr�������linux �ں�ѧϰ�ʼ��жԴ�
		�����ķ���( �����������ú���get_vm_area ֻ�Ǵ�����Ҫ���������ռ�Ĵ�С������
		�����ڲ��ͻ��������ռ�Ĵ�С��ȫ�������ַ���ݽṹ�������ҵ����ʵĵط�
		��Ȼ�����һ���������ݽṹ�������������е����������ַ�������ȷ����������
		�ṹ�е���ʼ��ַ����area->addr) ������ӳ��������ַ�ͷ�������ʼ��ַ��
		��vma->vm_start ��area->addr �����һ����ƫ�����proc->user_buffer_offset �������ڱ����ֵ��
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
		����ָ��������ڴ棬�����е�ÿ��Ԫ��Ϊһ��ָ�룬������������ý�ÿ��ָ��
		ָ��һ��ʵ�ʵ������ڴ��ҳ���ַ

		������ʼ���ַ���������ַ��ͨ������Ϳ���֪��ʵ����Ҫ���ٸ�����ҳ�棬
		Ȼ��ͷ�����ٸ�ָ��Ԫ�أ���Щָ��Ԫ�ع���һ�����飬��proc �����Աpages ����
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
	
	�ṹ��ȫ�Ǻ���ָ�롣����open��close��nopage  �ֱ������������Ĵ򿪡��رպͽ���ӳ�䡣Ϊ
	ʲôҪ����Щ������? ������Ϊ���ڲ�ͬ�����������ܻ���ҪһЩ��ͬ�ĸ��Ӳ���������ָ��
	nopage ָʾ����( ���) ҳ�治���ڴ��ж�����"ҳ�����" (page fault) �쳣ʱ��Ӧ���õĺ�����
*/

	vma->vm_ops = &binder_vm_ops; /* �趨vm_area_struct ���ݽṹ�Ĳ���������*/
	vma->vm_private_data = proc; /* �����ݽṹvm_area_struct �е�˽����������Ϊproc ֵ*/

	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) /* �������ڲ�����*/
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
	�˺������ڴ�binder ���豸�ļ�/dev/binder
	�κ�һ�����̼����ڵ������̶߳����Դ�һ��binder �豸

	�˺����Ĺ���:
	���ȷ���һ��binder_proc ���͵��ڴ�ռ䣬Ȼ�󽫵�ǰ���̵���Ϣ���浽�����ݽṹ�У���
	�����ڲ�����ر������г�ʼ����Ȼ��������ݽṹ��ӵ���binder_procs �������ȫ��
	������

	1����Ҫ����������һ��binder_proc �ռ�������binder ����
	2�����ӵ�ǰ�߳�/���̵����ü���������ֵ��binder_proc ��tsk �ֶ�
	3����ʼ��binder_proc ���У�������Ҫ����ʹ��INIT_LIST_HEAD ��ʼ������ͷtodo��ʹ��init_waitqueue_head��ʼ���ȴ�
		����wait������Ĭ�����ȼ���(default_priority)Ϊ��ǰ���̵�nice ֵ(ͨ��task nice �õ���ǰ���̵�nice ֵ)
	4������BINDER_STAT_PROC�Ķ����������ͨ��hlist_add_head�Ѵ�����binder_proc������ӵ�ȫ�ֵ�binder_proc �Ĺ�ϣ��
		�У�����һ�����κ�һ�����̾Ͷ����Է��ʵ��������̵�binder_proc ������
	5���ѵ�ǰ����(���߳�) ���߳����pid (pid ָ���߳�id) ��ֵ��proc ��pid �ֶΣ��������Ϊһ������id ( thread_group
		ָ���߳����еĵ�һ���̵߳�task_struct �ṹ)��ͬʱ�Ѵ�����binder_proc ����ָ�븳ֵ��filp ��private_data ����
		��������
	6����binder proc Ŀ¼�д���ֻ���ļ�/proc/binder/proc/$pid�����������ǰbinder proc �����״̬���ļ�����pid ������
		����Ҫע����ǣ���pid �ֶβ����ǵ�ǰ����/ �̵߳�id�������߳����pid��Ҳ�����߳����е�һ����
		��pid (��Ϊ�ǽ�current->grout_leader->pid ��ֵ����pid �ֶε�)�����⣬�ڴ������ļ�ʱ��ͬ��Ҳָ���˲�����
		�ļ��ĺ����ӿ�Ϊbinder_read_proc_proc ��������������Ǵ�����binder_proc ����proc�������ļ���Ӧ�Ĳ����ӿ�
		����Ϊ��������binder_proc �ṹ
*/
	struct binder_proc *proc;

	binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_open: %d:%d\n",  current->group_leader->pid, current->pid);

	proc = kzalloc(sizeof(*proc), GFP_KERNEL); /* Ϊbinder_proc �����ڴ�ռ�*/
	if (proc == NULL)
		return -ENOMEM;
	
	get_task_struct(current); /* ���ӵ��ô˺����Ľ��̿��ƿ�����ü���*/
	
	proc->tsk = current; /* */
	
	INIT_LIST_HEAD(&proc->todo);
	
	init_waitqueue_head(&proc->wait);
	
	proc->default_priority = task_nice(current);
	
	mutex_lock(&binder_lock);
	
	binder_stats_created(BINDER_STAT_PROC);
	
	hlist_add_head(&proc->proc_node, &binder_procs);/* ͨ��proc �����Աproc_node �����·����proc ���ݽṹ��ӵ�ȫ�ֹ�ϣ��binder_procs ��*/

	proc->pid = current->group_leader->pid;
	
	INIT_LIST_HEAD(&proc->delivered_death);
	
	filp->private_data = proc;
	
	mutex_unlock(&binder_lock);

	/* ����ֻ���ļ�/proc/binder/proc/$pid */
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
	struct binder_proc *proc = filp->private_data;

	binder_defer_work(proc, BINDER_DEFERRED_FLUSH);

	return 0;
}

static void binder_deferred_flush(struct binder_proc *proc)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
	struct binder_proc *proc = filp->private_data;
	debugfs_remove(proc->debugfs_entry); /* ɾ��open �����д�����/proc/binder/proc/$pid  �ļ�*/
	binder_defer_work(proc, BINDER_DEFERRED_RELEASE);

	return 0;
}

static void binder_deferred_release(struct binder_proc *proc)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
	seq_printf(m, "%s %d: %p size %zd:%zd %s\n",
				   prefix, buffer->debug_id, buffer->data,
				   buffer->data_size, buffer->offsets_size,
				   buffer->transaction ? "active" : "delivered");
}

static void print_binder_work(struct seq_file *m, const char *prefix,  const char *transaction_prefix, struct binder_work *w)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
	seq_printf(m, "  ref %d: desc %d %snode %d s %d w %d d %p\n", ref->debug_id, ref->desc, ref->node->proc ? "" : "dead ", ref->node->debug_id, ref->strong, ref->weak, ref->death);
}

static void print_binder_proc(struct seq_file *m, struct binder_proc *proc, int print_all)
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
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

	/* ����binder ��Ŀ¼�����˵�˽ڵ�Ϊ/proc/binder ���д���ʵ�ʲ���*/
	binder_debugfs_dir_entry_root = debugfs_create_dir("binder", NULL);

	/* ����proc �ļ�ϵͳ��binder Ŀ¼�����˵�˽ڵ�Ϊ/proc/binder/proc ���д���ʵ�ʲ���*/
	if (binder_debugfs_dir_entry_root)
		binder_debugfs_dir_entry_proc = debugfs_create_dir("proc", binder_debugfs_dir_entry_root);

	/* ע��misc �豸���豸�ڵ�Ϊ/dev/binder �����豸��Ϊ10���ýڵ���init ������handle_device_fd(device_fd) �����е���handle_device_event(&uevent) ����ִ������uevent-netlink �¼���"/dev" Ŀ¼�´���*/
	ret = misc_register(&binder_miscdev);
	
	if (binder_debugfs_dir_entry_root)
	{
		/*
			debugfs �ļ�ϵͳ
			
			1 Debugfs���
				Debugfs�ļ�ϵͳĿ����Ϊ������Ա�ṩ�����ں�����,�����������. ����֪
				��/proc�ļ�ϵͳ��ע���ǽ�����Ϣ��/sysfs��ע��one-value-per-file���Լ�����Debugfs��
				��ϵͳû����˶����ƣ������κ��ں�Ҫ�������Ϣ��

			2 Debugfsʹ��
				2.1 ��װ�ļ�ϵͳ
			    		Debugfsû�������豸������ط�ʽ��
			   		mount -t debugfs none /sys/kernel/debug
		*/
		/* �������漸���ļ� */
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
