/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "binder.h"

#define MAX_BIO_SIZE (1 << 30)

#define TRACE 0

#define LOG_TAG "Binder"
#include <cutils/log.h>

void bio_init_from_txn(struct binder_io *io, struct binder_txn *txn);

#if TRACE
void hexdump(void *_data, unsigned len)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	unsigned char *data = _data;
	unsigned count;

	for (count = 0; count < len; count++) 
	{
		if ((count & 15) == 0)
			fprintf(stderr,"%04x:", count);
		
		fprintf(stderr," %02x %c", *data, (*data < 32) || (*data > 126) ? '.' : *data);
		
		data++;
		
		if ((count & 15) == 15)
			fprintf(stderr,"\n");
	}
	
	if ((count & 15) != 0)
		fprintf(stderr,"\n");
}

void binder_dump_txn(struct binder_txn *txn)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_object *obj;
	unsigned *offs = txn->offs;
	unsigned count = txn->offs_size / 4;

	fprintf(stderr,"  target %p  cookie %p  code %08x  flags %08x\n", txn->target, txn->cookie, txn->code, txn->flags);
	fprintf(stderr,"  pid %8d  uid %8d  data %8d  offs %8d\n", txn->sender_pid, txn->sender_euid, txn->data_size, txn->offs_size);
	
	hexdump(txn->data, txn->data_size);
	
	while (count--) 
	{
		obj = (void*) (((char*) txn->data) + *offs++);
		fprintf(stderr,"  - type %08x  flags %08x  ptr %p  cookie %p\n", obj->type, obj->flags, obj->pointer, obj->cookie);
	}
}

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}
#else
#define hexdump(a,b) do{} while (0)
#define binder_dump_txn(txn)  do{} while (0)
#endif

#define BIO_F_SHARED    0x01  /* needs to be buffer freed */
#define BIO_F_OVERFLOW  0x02  /* ran out of space */
#define BIO_F_IOERROR   0x04
#define BIO_F_MALLOCED  0x08  /* needs to be free()'d */

struct binder_state
{
	int fd; /* 保存了打开驱动文件"/dev/binder" 的文件id，见binder_open 函数*/
	void *mapped; /* 保存了驱动mmap  映射后的返回值*/
	unsigned mapsize; /* 保存mmap 调用时的空间大小*/
};

struct binder_state *binder_open(unsigned mapsize)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数调用内核的binder 驱动进行binder 的打开，并相应的设置

		2、执行步骤:
			1、打开binder 驱动
			2、进行mmap 的内存映射
*/

	struct binder_state *bs;

	bs = malloc(sizeof(*bs));
	if (!bs) 
	{
		errno = ENOMEM;
		return 0;
	}

	bs->fd = open("/dev/binder", O_RDWR);
	if (bs->fd < 0) 
	{
		fprintf(stderr,"binder: cannot open device (%s)\n", strerror(errno));
		goto fail_open;
	}

	bs->mapsize = mapsize;
	bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
	if (bs->mapped == MAP_FAILED) 
	{
		fprintf(stderr,"binder: cannot map device (%s)\n", strerror(errno));
		goto fail_map;
	}

	/* TODO: check version */

	return bs;

fail_map:
	close(bs->fd);
	
fail_open:
	free(bs);
	
	return 0;
}

void binder_close(struct binder_state *bs)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、关闭或释放main 函数中调用binder_open 打开时申请的资源
*/
	munmap(bs->mapped, bs->mapsize);
	close(bs->fd);
	free(bs);
}

int binder_become_context_manager(struct binder_state *bs)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、对驱动进行设置，告诉Binder Kernel 驱动程序这是一个服务管理进程
*/
    	return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}

int binder_write(struct binder_state *bs, void *data, unsigned len)
{
/*
	参数:
		1、bs	: 传入open 时分配的内存空间( 里面保存着打开的binder 驱动文件的id )
		2、data	: 传入要写的数据buffer 地址
		3、len	: 传入数据的长度
		
	返回:
		1、
		
	说明:
		1、调用内核的驱动进行数据写入
*/
	struct binder_write_read bwr;
	int res;
	bwr.write_size = len;
	bwr.write_consumed = 0;
	bwr.write_buffer = (unsigned) data;
	bwr.read_size = 0;
	bwr.read_consumed = 0;
	bwr.read_buffer = 0;
	res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
	if (res < 0) 
	{
		fprintf(stderr,"binder_write: ioctl failed (%s)\n",strerror(errno));
	}
	return res;
}

void binder_send_reply(struct binder_state *bs, struct binder_io *reply, void *buffer_to_free, int status)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct 
	{
		uint32_t cmd_free;
		void *buffer;
		uint32_t cmd_reply;
		struct binder_txn txn;
	} __attribute__((packed)) data;

	data.cmd_free = BC_FREE_BUFFER;
	data.buffer = buffer_to_free;
	data.cmd_reply = BC_REPLY;
	data.txn.target = 0;
	data.txn.cookie = 0;
	data.txn.code = 0;
	
	if (status)
	{
		data.txn.flags = TF_STATUS_CODE;
		data.txn.data_size = sizeof(int);
		data.txn.offs_size = 0;
		data.txn.data = &status;
		data.txn.offs = 0;
	}
	else
	{
		data.txn.flags = 0;
		data.txn.data_size = reply->data - reply->data0;
		data.txn.offs_size = ((char*) reply->offs) - ((char*) reply->offs0);
		data.txn.data = reply->data0;
		data.txn.offs = reply->offs0;
	}
	
	binder_write(bs, &data, sizeof(data));
}

int binder_parse(struct binder_state *bs, struct binder_io *bio, uint32_t *ptr, uint32_t size, binder_handler func)
{
/*
	参数:
		1、bs	: 传入open 时分配的内存空间( 里面保存着打开的binder 驱动文件的id )
		2、bio	: 
		3、ptr	: 待分析的数据
		4、size	: 数据长度
		5、func	: 传入一个函数，实质就是函数svcmgr_handler
		
	返回:
		1、
		
	说明:
		1、
*/
	int r = 1;
	uint32_t *end = ptr + (size / 4); /* 转换为4 字节为单位*/

	while (ptr < end) 
	{
		uint32_t cmd = *ptr++;
		
		#if TRACE
		fprintf(stderr,"%s:\n", cmd_name(cmd));
		#endif
		
		switch(cmd) 
		{
			case BR_NOOP:
				break;
				
			case BR_TRANSACTION_COMPLETE:
				break;
				
			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
				#if TRACE
				fprintf(stderr,"  %08x %08x\n", ptr[0], ptr[1]);
				#endif
				
				ptr += 2;
				break;
				
			case BR_TRANSACTION:
				{
					struct binder_txn *txn = (void *) ptr;
					
					if ((end - ptr) * sizeof(uint32_t) < sizeof(struct binder_txn)) 
					{
						LOGE("parse: txn too small!\n");
						return -1;
					}
					
					binder_dump_txn(txn);
					
					if (func)
					{
						unsigned rdata[256/4];
						struct binder_io msg;
						struct binder_io reply;
						int res;

						bio_init(&reply, rdata, sizeof(rdata), 4);
						bio_init_from_txn(&msg, txn);
						
						res = func(bs, txn, &msg, &reply); /* 调用函数svcmgr_handler 进行分析*/
						
						binder_send_reply(bs, &reply, txn->data, res);
					}
					
					ptr += sizeof(*txn) / sizeof(uint32_t);
					
					break;
				}
			
			case BR_REPLY: 
				{
					struct binder_txn *txn = (void*) ptr;
					
					if ((end - ptr) * sizeof(uint32_t) < sizeof(struct binder_txn)) 
					{
						LOGE("parse: reply too small!\n");
						return -1;
					}
					
					binder_dump_txn(txn);
					
					if (bio) 
					{
						bio_init_from_txn(bio, txn);
						bio = 0;
					} 
					else 
					{
						/* todo FREE BUFFER */
					}
					
					ptr += (sizeof(*txn) / sizeof(uint32_t));
					r = 0;
					
					break;
				}
			
			case BR_DEAD_BINDER: 
				{
					struct binder_death *death = (void*) *ptr++;
					death->func(bs, death->ptr);
					break;
				}
			
			case BR_FAILED_REPLY:
				r = -1;
				break;
				
			case BR_DEAD_REPLY:
				r = -1;
				break;
				
			default:
				LOGE("parse: OOPS %d\n", cmd);
				return -1;
		}
	}

	return r;
}

void binder_acquire(struct binder_state *bs, void *ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、向binder 驱动发送数据，申请
*/
	uint32_t cmd[2];
	cmd[0] = BC_ACQUIRE;
	cmd[1] = (uint32_t) ptr;
	binder_write(bs, cmd, sizeof(cmd));
}

void binder_release(struct binder_state *bs, void *ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、向binder 驱动发送数据，释放
*/
	uint32_t cmd[2];
	cmd[0] = BC_RELEASE;
	cmd[1] = (uint32_t) ptr;
	binder_write(bs, cmd, sizeof(cmd));
}

void binder_link_to_death(struct binder_state *bs, void *ptr, struct binder_death *death)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	uint32_t cmd[3];
	cmd[0] = BC_REQUEST_DEATH_NOTIFICATION;
	cmd[1] = (uint32_t) ptr;
	cmd[2] = (uint32_t) death;
	binder_write(bs, cmd, sizeof(cmd));
}


int binder_call(struct binder_state *bs, struct binder_io *msg, struct binder_io *reply, void *target, uint32_t code)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	int res;

	struct binder_write_read bwr;
	
	struct 
	{
		uint32_t cmd;
		struct binder_txn txn;
	} writebuf;
	
	unsigned readbuf[32];

	if (msg->flags & BIO_F_OVERFLOW)
	{
		fprintf(stderr,"binder: txn buffer overflow\n");
		goto fail;
	}

	writebuf.cmd = BC_TRANSACTION;
	writebuf.txn.target = target;
	writebuf.txn.code = code;
	writebuf.txn.flags = 0;
	writebuf.txn.data_size = msg->data - msg->data0;
	writebuf.txn.offs_size = ((char*) msg->offs) - ((char*) msg->offs0);
	writebuf.txn.data = msg->data0;
	writebuf.txn.offs = msg->offs0;

	bwr.write_size = sizeof(writebuf);
	bwr.write_consumed = 0;
	bwr.write_buffer = (unsigned) &writebuf;

	hexdump(msg->data0, msg->data - msg->data0);
	for (;;) 
	{
		bwr.read_size = sizeof(readbuf);
		bwr.read_consumed = 0;
		bwr.read_buffer = (unsigned) readbuf;

		res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

		if (res < 0) 
		{
			fprintf(stderr,"binder: ioctl failed (%s)\n", strerror(errno));
			goto fail;
		}

		res = binder_parse(bs, reply, readbuf, bwr.read_consumed, 0);
		if (res == 0) 
			return 0;
		
		if (res < 0) 
			goto fail;
	}

fail:
	memset(reply, 0, sizeof(*reply));
	reply->flags |= BIO_F_IOERROR;
	
	return -1;
}

void binder_loop(struct binder_state *bs, binder_handler func)
{
/*
	参数:
		1、bs	: 传入open 时分配的内存空间( 里面保存着打开的binder 驱动文件的id )
		2、func	: 传入一个函数，实质就是函数svcmgr_handler
		
	返回:
		1、
		
	说明:
		1、
*/
	int res;
	struct binder_write_read bwr;
	unsigned readbuf[32];

	bwr.write_size = 0;
	bwr.write_consumed = 0;
	bwr.write_buffer = 0;

	readbuf[0] = BC_ENTER_LOOPER;
	binder_write(bs, readbuf, sizeof(unsigned));

	for (;;)
	{
		/* 此处执行了一次读的操作，即读取32  字节回来*/
		bwr.read_size = sizeof(readbuf);
		bwr.read_consumed = 0;
		bwr.read_buffer = (unsigned) readbuf;

		res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr); /* 如果没有要处理的请求进程将挂起*/
		if (res < 0)
		{
			LOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
			break;
		}

		res = binder_parse(bs, 0, readbuf, bwr.read_consumed, func);
		if (res == 0) 
		{
			LOGE("binder_loop: unexpected reply?!\n");
			break;
		}
		
		if (res < 0) 
		{
			LOGE("binder_loop: io error %d %s\n", res, strerror(errno));
			break;
		}
	}
}

void bio_init_from_txn(struct binder_io *bio, struct binder_txn *txn)
{
/*
	参数:
		1、bio		: 传入binder_io 的数据结构
		2、txn		: 传入binder_txn 指针数据，用此参数的内容对参数1 进行填充
		
	返回:
		1、
		
	说明:
		1、
*/
	bio->data = bio->data0 = txn->data;
	bio->offs = bio->offs0 = txn->offs;
	bio->data_avail = txn->data_size;
	bio->offs_avail = txn->offs_size / 4;
	bio->flags = BIO_F_SHARED;
}

void bio_init(struct binder_io *bio, void *data, uint32_t maxdata, uint32_t maxoffs)
{
/*
	参数:
		1、bio		: 传入binder_io 的数据结构
		2、data		: 传入数据指针
		3、maxdata	: 传入数据buffer 最大字节数
		4、maxoffs	: 传入数据偏移的最大数量( 4 字节为单位的)
		
	返回:
		1、
		
	说明:
		1、此函数实现用后三个参数对第一个参数的各个域成员进行填充
		

					-------------------------------------------------------------
			data		|XXXXXXXXXXXXX	|											|
					-------------------------------------------------------------
					^				^											^
					^				^											^
					^				^											^
				地址1			地址2										地址3


			maxdata 	= ( 地址3 )  -  ( 地址1 )
			maxoffs	= ( 地址2 )  -  ( 地址1 )
		
*/
	uint32_t n = maxoffs * sizeof(uint32_t);

	if (n > maxdata) 
	{
		bio->flags = BIO_F_OVERFLOW;
		bio->data_avail = 0;
		bio->offs_avail = 0;
		return;
	}

	bio->data = bio->data0 = data + n;		/* data、data0 均被设置为地址2 的值											*/
	bio->offs = bio->offs0 = data;			/* offs、offs0 均被设置为地址1 的值												*/
	bio->data_avail = maxdata - n;		/* data_avail  被设置为地址3 减去地址2 的大小，即图中的空白处大小	*/	
	bio->offs_avail = maxoffs;				/* offs_avail 被设置为maxoffs，即图中XXX 空间的大小							*/
	bio->flags = 0;
}

static void *bio_alloc(struct binder_io *bio, uint32_t size)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、与函数bio_alloc_obj 有一定的区别，见bio_alloc_obj 的说明
		2、结合函数bio_init 中的图示说明，此函数实现了从图示中的空白处分配一个size 大小的空间，并向
			后更新data 等域成员参数


			此函数被调用前数据空间示意图:
							-------------------------------------------------------------
					data		|XXXXXXXXXXXXX	|											|
							-------------------------------------------------------------
							^				^											^
							^				^											^
							^				^											^
						地址1			bio->data									地址3

				
			此函数被调用后数据空间示意图:
							-------------------------------------------------------------
					data		|XXXXXXXXXXXXX	|aaaaaaaaaaaaaaa|							|
							-------------------------------------------------------------
							^				^				^							^
							^				^				^							^
							^				^				^							^
						地址1			返回值		bio->data					地址3

					aaa 空间的大小为size 的值，即要从数据buffer 中分配的需要使用的空间
*/
	size = (size + 3) & (~3);
	if (size > bio->data_avail)
	{
		bio->flags |= BIO_F_OVERFLOW;
		return 0;
	} 
	else 
	{
		void *ptr = bio->data;
		bio->data += size;
		bio->data_avail -= size;
		return ptr;
	}
}

void binder_done(struct binder_state *bs, struct binder_io *msg, struct binder_io *reply)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、向binder 驱动发送数据
*/
	if (reply->flags & BIO_F_SHARED) 
	{
		uint32_t cmd[2];
		cmd[0] = BC_FREE_BUFFER;
		cmd[1] = (uint32_t) reply->data0;
		binder_write(bs, cmd, sizeof(cmd));
		reply->flags = 0;
	}
}

static struct binder_object *bio_alloc_obj(struct binder_io *bio)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、结合函数bio_alloc 中的图示说明，此函数为分配一个binder_object 的空间，与bio_alloc 有一定的区别

			主要区别在于bio_alloc 函数可以分配任意大小的空间，并且不对XXX  区域的数据进行更新
			而此函数则在分配binder_object 空间的同时还需要对XXX  区域的数据进行更新，即域成员offs_avail 的值以及offs 的内容
*/
	struct binder_object *obj;

	obj = bio_alloc(bio, sizeof(*obj));

	if (obj && bio->offs_avail) 
	{
		bio->offs_avail--; /* 如果此值减到0 了，则不允许再进行分配了，见bio_init 对此值的赋值*/
		*bio->offs++ = ((char*) obj) - ((char*) bio->data0); /* XXX 空间的为一个unsigned int 数组，则保存着每个分配的binder_object 地址*/
		return obj;
	}

	bio->flags |= BIO_F_OVERFLOW;
	return 0;
}

void bio_put_uint32(struct binder_io *bio, uint32_t n)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、从bio 中分配一个整形空间，并用n 对其进行赋值
*/
	uint32_t *ptr = bio_alloc(bio, sizeof(n));
	if (ptr)
	    *ptr = n;
}

void bio_put_obj(struct binder_io *bio, void *ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数实现从bio 中分配一个binder_object 空间，然后对其进行填充
*/
	struct binder_object *obj;

	obj = bio_alloc_obj(bio);
	if (!obj)
		return;

	obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
	obj->type = BINDER_TYPE_BINDER;
	obj->pointer = ptr;
	obj->cookie = 0;
}

void bio_put_ref(struct binder_io *bio, void *ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、见代码
*/
	struct binder_object *obj;

	if (ptr)
		obj = bio_alloc_obj(bio);
	else
		obj = bio_alloc(bio, sizeof(*obj));

	if (!obj)
		return;

	obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
	obj->type = BINDER_TYPE_HANDLE;
	obj->pointer = ptr;
	obj->cookie = 0;
}

void bio_put_string16(struct binder_io *bio, const uint16_t *str)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、见代码
*/
	uint32_t len;
	uint16_t *ptr;

	if (!str)
	{
		bio_put_uint32(bio, 0xffffffff);
		return;
	}

	len = 0;
	
	while (str[len]) 
		len++;

	if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) 
	{
		bio_put_uint32(bio, 0xffffffff);
		return;
	}

	bio_put_uint32(bio, len);
	len = (len + 1) * sizeof(uint16_t);
	ptr = bio_alloc(bio, len);
	
	if (ptr)
		memcpy(ptr, str, len);
}

void bio_put_string16_x(struct binder_io *bio, const char *_str)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、见代码
*/
	unsigned char *str = (unsigned char*) _str;
	uint32_t len;
	uint16_t *ptr;

	if (!str) 
	{
		bio_put_uint32(bio, 0xffffffff);
		return;
	}

	len = strlen(_str);

	if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) 
	{
		bio_put_uint32(bio, 0xffffffff);
		return;
	}

	bio_put_uint32(bio, len);
	ptr = bio_alloc(bio, (len + 1) * sizeof(uint16_t));
	if (!ptr)
		return;

	while (*str)
		*ptr++ = *str++;
	
	*ptr++ = 0;
}

static void *bio_get(struct binder_io *bio, uint32_t size)
{
/*
	参数:
		1、bio	: 传入binder_io 的数据结构
		2、size	: 传入一个希望获取的数据长度
		
	返回:
		1、
		
	说明:
		1、函数执行过程:
			A、先判断结构体中的有效数据的长度和要读取的数据长度，如果有效数据的长度比要读取的数据长度还小，则出错了
			B、更新结构体中数据指针的位置( 从起始处向后移动读取的长度)
			C、更新结构体中有效数据的长度值( 将读取的长度数减掉)
			D、返回要读取到的数据的首地址

			例如:
			
				调用为bio_get ( bio, 12 );
				
					调用时参数bio  的值为
						bio->data 		= "0000111122223333444455556666777788889999"  	//--> data 指向第一个0 的地址
						bio->data_avail	= 40

					调用后参数bio 的值为
						bio->data 		= "3333444455556666777788889999"  	//--> data 指向第一个3 的地址，即向后移了12  个字节
						bio->data_avail	= 28 (40 - 12)

					返回的值为0000 处的地址
				
*/
	size = (size + 3) & (~3); /* 按照4  字节边界对齐*/

	if (bio->data_avail < size)
	{
		bio->data_avail = 0;
		bio->flags |= BIO_F_OVERFLOW;
		return 0;
	}  
	else
	{
		void *ptr = bio->data;
		bio->data += size;
		bio->data_avail -= size;
		return ptr;
	}
}

uint32_t bio_get_uint32(struct binder_io *bio)
{
/*
	参数:
		1、bio	: 传入binder_io 的数据结构
		
	返回:
		1、
		
	说明:
		1、见函数bio_get 的说明
		2、从传入的bio 的数据buffer 中获取一个int 型的数据，同时会更新bio 中的数据指针，即向后移动一个整形的字节数
*/
	uint32_t *ptr = bio_get(bio, sizeof(*ptr));
	return ptr ? *ptr : 0;
}

uint16_t *bio_get_string16(struct binder_io *bio, unsigned *sz)
{
/*
	参数:
		1、bio	: 传入binder_io 的数据结构
		2、sz	: 用于返回获得到的无符号16 位数组的长度
		
	返回:
		1、
		
	说明:
		1、此函数的执行过程:
			A、先从bio 的data 中取出一个整数，即为长度len
			B、然后再从bio 的data 中取出len+1 个无符号的16 位的数，即返回此16 位无符号数据串的指针
*/
	unsigned len;
	len = bio_get_uint32(bio);
	if (sz)
		*sz = len;
	
	return bio_get(bio, (len + 1) * sizeof(uint16_t));
}

static struct binder_object *_bio_get_obj(struct binder_io *bio)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	unsigned n;
	unsigned off = bio->data - bio->data0;

	/* TODO: be smarter about this? */
	for (n = 0; n < bio->offs_avail; n++) 
	{
		if (bio->offs[n] == off)
			return bio_get(bio, sizeof(struct binder_object));
	}

	bio->data_avail = 0;
	bio->flags |= BIO_F_OVERFLOW;
	return 0;
}

void *bio_get_ref(struct binder_io *bio)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct binder_object *obj;

	obj = _bio_get_obj(bio);
	if (!obj)
		return 0;

	if (obj->type == BINDER_TYPE_HANDLE)
		return obj->pointer;

	return 0;
}
