/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <private/android_filesystem_config.h>

#include "binder.h"

#if 0
#define LOGI(x...) fprintf(stderr, "svcmgr: " x)
#define LOGE(x...) fprintf(stderr, "svcmgr: " x)
#else
#define LOG_TAG "ServiceManager"
#include <cutils/log.h>
#endif

/* TODO:
 * These should come from a config file or perhaps be
 * based on some namespace rules of some sort (media
 * uid can register media.*, etc)
 */
static struct {
	unsigned uid;
	const char *name;
} allowed[] = {
#ifdef LVMX
    { AID_MEDIA, "com.lifevibes.mx.ipc" },
#endif
    { AID_MEDIA, "media.audio_flinger" },
    { AID_MEDIA, "media.player" },
    { AID_MEDIA, "media.camera" },
    { AID_MEDIA, "media.audio_policy" },
    { AID_NFC,   "nfc" },
    { AID_RADIO, "radio.phone" },
    { AID_RADIO, "radio.sms" },
    { AID_RADIO, "radio.phonesubinfo" },
    { AID_RADIO, "radio.simphonebook" },
/* TODO: remove after phone services are updated: */
    { AID_RADIO, "phone" },
    { AID_RADIO, "sip" },
    { AID_RADIO, "isms" },
    { AID_RADIO, "iphonesubinfo" },
    { AID_RADIO, "simphonebook" },
};

void *svcmgr_handle;

const char *str8(uint16_t *x)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	static char buf[128];
	unsigned max = 127;
	char *p = buf;

	if (x)
	{
		while (*x && max--)
		{
			*p++ = *x++;
		}
	}
	*p++ = 0;
	return buf;
}

int str16eq(uint16_t *a, const char *b)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	while (*a && *b)
		if (*a++ != *b++) 
			return 0;
		
	if (*a || *b)
		return 0;
	
	return 1;
}

int svc_can_register(unsigned uid, uint16_t *name)
{
/*
	参数:
		1、uid		: 传入一个uid
		2、name	: 传入一个要注册服务的名字
		
	返回:
		1、
		
	说明:
		1、实质就是在全局变量allowed  中查找，即allowed  中事先定义好了一些可以注册的服务，传入
			的参数如果与allowed  中的某个单元匹配，则表示可以进行注册的
*/
	unsigned n;

	if ((uid == 0) || (uid == AID_SYSTEM))
		return 1;

	for (n = 0; n < sizeof(allowed) / sizeof(allowed[0]); n++)
		if ((uid == allowed[n].uid) && str16eq(name, allowed[n].name))
			return 1;

	return 0;
}

struct svcinfo 
{
	/* 注册到serviceManager  中的所有服务都是保存在这个数据结构为单元的链表中的*/
	
	struct svcinfo *next; /* 指向下一个单元，构成链表*/
	void *ptr; /* 相当于指向具体的服务*/
	struct binder_death death;
	unsigned len; /* 服务名字的长度*/
	uint16_t name[0]; /* 服务的名字*/
};

struct svcinfo *svclist = 0; /* 见数据结构svcinfo  的定义*/

struct svcinfo *find_svc(uint16_t *s16, unsigned len)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、实质就是在全局链表svclist  中查找与传入参数相匹配的单元
*/
	struct svcinfo *si;

	for (si = svclist; si; si = si->next) 
	{
		if ((len == si->len) && !memcmp(s16, si->name, len * sizeof(uint16_t))) 
		{
			return si;
		}
	}
	return 0;
}

void svcinfo_death(struct binder_state *bs, void *ptr)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct svcinfo *si = ptr;
	LOGI("service '%s' died\n", str8(si->name));
	if (si->ptr) 
	{
		binder_release(bs, si->ptr);
		si->ptr = 0;
	}   
}



uint16_t svcmgr_id[] = 
{ 
	'a','n','d','r','o','i','d','.','o','s','.',
	'I','S','e','r','v','i','c','e','M','a','n','a','g','e','r' 
};
  

void *do_find_service(struct binder_state *bs, uint16_t *s, unsigned len)
{
/*
	参数:
		1、bs	: 此参数在这个函数中没有使用
		2、s	: 相当于传入一个服务的名字
		3、len	: 相当于服务名字的长度
		
	返回:
		1、
		
	说明:
		1、参看函数find_svc  的说明，此函数是找到具体的服务，即si->ptr
*/
	struct svcinfo *si;
	si = find_svc(s, len);

	//    LOGI("check_service('%s') ptr = %p\n", str8(s), si ? si->ptr : 0);
	if (si && si->ptr) 
	{
		return si->ptr;
	} 
	else 
	{
		return 0;
	}
}

int do_add_service(struct binder_state *bs, uint16_t *s, unsigned len, void *ptr, unsigned uid)
{
/*
	参数:
		1、bs	: 函数binder_open  中创建的此实体
		2、s	: 相当于传入一个服务的名字
		3、len	: 相当于服务名字的长度
		4、ptr	: 指向具体服务的地址
		5、uid	: 服务的uid ，见全局变量allowed  定义中的uid  设定值
		
	返回:
		1、
		
	说明:
		1、
*/
	struct svcinfo *si;
	//    LOGI("add_service('%s',%p) uid=%d\n", str8(s), ptr, uid);

	if (!ptr || (len == 0) || (len > 127))
		return -1;

	if (!svc_can_register(uid, s)) /* 判断是否允许注册*/
	{
		LOGE("add_service('%s',%p) uid=%d - PERMISSION DENIED\n",str8(s), ptr, uid);
		return -1;
	}

	si = find_svc(s, len); /* 判断是否已经添加到服务队列中*/
	if (si) /* 是*/
	{
		if (si->ptr) 
		{
			LOGE("add_service('%s',%p) uid=%d - ALREADY REGISTERED\n", str8(s), ptr, uid);
			return -1;
		}
		si->ptr = ptr;
	} 
	else /* 否*/
	{
		si = malloc(sizeof(*si) + (len + 1) * sizeof(uint16_t)); /* 分配一个服务单元的内存空间*/
		if (!si) 
		{
			LOGE("add_service('%s',%p) uid=%d - OUT OF MEMORY\n", str8(s), ptr, uid);
			return -1;
		}

		/* 用传入的参数等对刚刚分配的单元进行填充*/
		si->ptr = ptr;
		si->len = len;
		memcpy(si->name, s, (len + 1) * sizeof(uint16_t));
		si->name[len] = '\0';
		si->death.func = svcinfo_death;
		si->death.ptr = si;
		si->next = svclist; /* 将其插入到服务队列中*/
		svclist = si;
	}

	binder_acquire(bs, ptr); /* binder  申请*/
	
	binder_link_to_death(bs, ptr, &si->death);
	
	return 0;
}

int svcmgr_handler(struct binder_state *bs, struct binder_txn *txn, struct binder_io *msg, struct binder_io *reply)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct svcinfo *si;
	uint16_t *s;
	unsigned len;
	void *ptr;
	uint32_t strict_policy;

	//    LOGI("target=%p code=%d pid=%d uid=%d\n",
	//         txn->target, txn->code, txn->sender_pid, txn->sender_euid);

	if (txn->target != svcmgr_handle)
		return -1;

	// Equivalent to Parcel::enforceInterface(), reading the RPC
	// header with the strict mode policy mask and the interface name.
	// Note that we ignore the strict_policy and don't propagate it
	// further (since we do no outbound RPCs anyway).
	
	strict_policy = bio_get_uint32(msg);
	
	s = bio_get_string16(msg, &len);
	
	if ((len != (sizeof(svcmgr_id) / 2)) || memcmp(svcmgr_id, s, sizeof(svcmgr_id))) 
	{
		fprintf(stderr,"invalid id %s\n", str8(s));
		return -1;
	}

	switch(txn->code) 
	{
		case SVC_MGR_GET_SERVICE:
		case SVC_MGR_CHECK_SERVICE:
			s = bio_get_string16(msg, &len);
			ptr = do_find_service(bs, s, len);
			if (!ptr)
				break;
			bio_put_ref(reply, ptr);
			return 0;

		case SVC_MGR_ADD_SERVICE:
			s = bio_get_string16(msg, &len);
			ptr = bio_get_ref(msg);
			if (do_add_service(bs, s, len, ptr, txn->sender_euid))
				return -1;
			break;

		case SVC_MGR_LIST_SERVICES: 
			{
				unsigned n = bio_get_uint32(msg);

				si = svclist;
				while ((n-- > 0) && si)
					si = si->next;
				
				if (si) 
				{
					bio_put_string16(reply, si->name);
					return 0;
				}
				return -1;
			}
		
		default:
			LOGE("unknown code %d\n", txn->code);
			return -1;
	}

	bio_put_uint32(reply, 0);
	return 0;
}


int main(int argc, char **argv)
{
/*
	ServiceMananger进程注册过程源码分析：
	Service Manager Process（Service_manager.c）:
    	Service_manager为其他进程的Service提供管理，这个服务程序必须在Android Runtime起来之
    	前运行，否则Android JAVA Vm ActivityManagerService无法注册。
*/
	struct binder_state *bs;
	void *svcmgr = BINDER_SERVICE_MANAGER; /* BINDER_SERVICE_MANAGER 是服务管理进程的句柄，如果客户端进程获取Service 时所使用的句柄与此不符，Service Manager 将不接受Client 的请求。*/

	bs = binder_open(128*1024); /* 参看函数分析*/

	if (binder_become_context_manager(bs))  /* 通知驱动此为一个serviceManager  */
	{
		LOGE("cannot become context manager (%s)\n", strerror(errno));
		return -1;
	}

	svcmgr_handle = svcmgr;
	binder_loop(bs, svcmgr_handler); /* 进入service manager  主线程*/
	
	return 0;
}
