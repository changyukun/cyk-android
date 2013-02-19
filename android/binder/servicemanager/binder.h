/* Copyright 2008 The Android Open Source Project
 */

#ifndef _BINDER_H_
#define _BINDER_H_

#include <sys/ioctl.h>
#include <linux/binder.h>

struct binder_state;

struct binder_object
{
    uint32_t type;
    uint32_t flags;
    void *pointer;
    void *cookie;
};

struct binder_txn
{
    void *target;
    void *cookie;
    uint32_t code;
    uint32_t flags;

    uint32_t sender_pid;
    uint32_t sender_euid;

    uint32_t data_size;
    uint32_t offs_size;
    void *data;
    void *offs;
};

struct binder_io
{
	/*
		见函数bio_init 对此数据结构的分析及示意图
	*/
	
	char *data;            	/* 指向数据的指针，数据存放的起始地址					*/			/* pointer to read/write from */
	uint32_t *offs;        	/* array of offsets */
	uint32_t data_avail;   	/* 有效数据的长度，即data 指针开始的有效数据的长度	*/			/* bytes available in data buffer */
	uint32_t offs_avail;   	/* 见函数bio_alloc_obj 的代码											*/			/* entries available in offsets array */

	char *data0;           		/* start of data buffer */
	uint32_t *offs0;       		/* start of offsets buffer */
	uint32_t flags;
	uint32_t unused;
};

struct binder_death {
    void (*func)(struct binder_state *bs, void *ptr);
    void *ptr;
};    

/* the one magic object */
#define BINDER_SERVICE_MANAGER ((void*) 0)  /* BINDER_SERVICE_MANAGER 是服务管理进程的句柄，如果客户端进程获取Service 时所使用的句柄与此不符，Service Manager 将不接受Client 的请求。*/

#define SVC_MGR_NAME "android.os.IServiceManager"

enum {
    SVC_MGR_GET_SERVICE = 1,
    SVC_MGR_CHECK_SERVICE,
    SVC_MGR_ADD_SERVICE,
    SVC_MGR_LIST_SERVICES,
};

typedef int (*binder_handler)(struct binder_state *bs,
                              struct binder_txn *txn,
                              struct binder_io *msg,
                              struct binder_io *reply);

struct binder_state *binder_open(unsigned mapsize);
void binder_close(struct binder_state *bs);

/* initiate a blocking binder call
 * - returns zero on success
 */
int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                void *target, uint32_t code);

/* release any state associate with the binder_io
 * - call once any necessary data has been extracted from the
 *   binder_io after binder_call() returns
 * - can safely be called even if binder_call() fails
 */
void binder_done(struct binder_state *bs,
                 struct binder_io *msg, struct binder_io *reply);

/* manipulate strong references */
void binder_acquire(struct binder_state *bs, void *ptr);
void binder_release(struct binder_state *bs, void *ptr);

void binder_link_to_death(struct binder_state *bs, void *ptr, struct binder_death *death);

void binder_loop(struct binder_state *bs, binder_handler func);

int binder_become_context_manager(struct binder_state *bs);

/* allocate a binder_io, providing a stack-allocated working
 * buffer, size of the working buffer, and how many object
 * offset entries to reserve from the buffer
 */
void bio_init(struct binder_io *bio, void *data,
           uint32_t maxdata, uint32_t maxobjects);

void bio_destroy(struct binder_io *bio);

void bio_put_obj(struct binder_io *bio, void *ptr);
void bio_put_ref(struct binder_io *bio, void *ptr);
void bio_put_uint32(struct binder_io *bio, uint32_t n);
void bio_put_string16(struct binder_io *bio, const uint16_t *str);
void bio_put_string16_x(struct binder_io *bio, const char *_str);

uint32_t bio_get_uint32(struct binder_io *bio);
uint16_t *bio_get_string16(struct binder_io *bio, uint32_t *sz);
void *bio_get_obj(struct binder_io *bio);
void *bio_get_ref(struct binder_io *bio);

#endif
