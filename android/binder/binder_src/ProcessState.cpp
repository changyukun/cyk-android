/*
 * Copyright (C) 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "ProcessState"

#include <cutils/process_name.h>

#include <binder/ProcessState.h>

#include <utils/Atomic.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <utils/Log.h>
#include <utils/String8.h>
#include <binder/IServiceManager.h>
#include <utils/String8.h>
#include <utils/threads.h>

#include <private/binder/binder_module.h>
#include <private/binder/Static.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define BINDER_VM_SIZE ((1*1024*1024) - (4096 *2))

static bool gSingleProcess = false;


// ---------------------------------------------------------------------------

namespace android {
 
// Global variables
int                 mArgC;
const char* const*  mArgV;
int                 mArgLen;

class PoolThread : public Thread
{
public:
	PoolThread(bool isMain) : mIsMain(isMain)
	{
	}

protected:
	virtual bool threadLoop()
	{
		IPCThreadState::self()->joinThreadPool(mIsMain);
		return false;
	}

	const bool mIsMain;
};

sp<ProcessState> ProcessState::self()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、调用此函数才真正的new  了一个实例ProcessState 
*/
	if (gProcess != NULL) 
		return gProcess;

	AutoMutex _l(gProcessMutex);
	
	if (gProcess == NULL) 
		gProcess = new ProcessState;
	
	return gProcess;
}

void ProcessState::setSingleProcess(bool singleProcess)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	gSingleProcess = singleProcess;
}


void ProcessState::setContextObject(const sp<IBinder>& object)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	setContextObject(object, String16("default"));
}

sp<IBinder> ProcessState::getContextObject(const sp<IBinder>& caller)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (supportsProcesses())/* 根据打开设备驱动是否成功判断是否支持process  ，成功*/
	{
		return getStrongProxyForHandle(0);/* 见函数内部分析*/
	}
	else/* binder 驱动打开不成功*/
	{
		return getContextObject(String16("default"), caller);
	}
}

void ProcessState::setContextObject(const sp<IBinder>& object, const String16& name)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	AutoMutex _l(mLock);
	mContexts.add(name, object);
}

sp<IBinder> ProcessState::getContextObject(const String16& name, const sp<IBinder>& caller)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mLock.lock();
	sp<IBinder> object(mContexts.indexOfKey(name) >= 0 ? mContexts.valueFor(name) : NULL);
	mLock.unlock();

	//printf("Getting context object %s for %p\n", String8(name).string(), caller.get());

	if (object != NULL)
		return object;

	// Don't attempt to retrieve contexts if we manage them
	if (mManagesContexts)
	{
		LOGE("getContextObject(%s) failed, but we manage the contexts!\n",String8(name).string());
		return NULL;
	}

	IPCThreadState* ipc = IPCThreadState::self();
	
	{
		Parcel data, reply;
		// no interface token on this magic transaction
		data.writeString16(name);
		data.writeStrongBinder(caller);
		status_t result = ipc->transact(0 /*magic*/, 0, data, &reply, 0);
		if (result == NO_ERROR) 
		{
			object = reply.readStrongBinder();
		}
	}

	ipc->flushCommands();

	if (object != NULL) 
		setContextObject(object, name);

	return object;
}

bool ProcessState::supportsProcesses() const
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、实质就是判断binder  驱动文件"/dev/binder"  是否在此进程中打开，mDriverFD >= 0  表示已经打开
*/
    	return mDriverFD >= 0;
}

void ProcessState::startThreadPool()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、启动线程池
		2、---------ccyykk------->>  启动线程looper  第1  步骤
*/
	AutoMutex _l(mLock);
	if (!mThreadPoolStarted)/* 如果还没启动，则启动*/
	{
		mThreadPoolStarted = true;
		spawnPooledThread(true); /* ---------ccyykk------->>  启动线程looper  第2  步骤*/
	}
}

bool ProcessState::isContextManager(void) const
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mManagesContexts;
}

bool ProcessState::becomeContextManager(context_check_func checkFunc, void* userData)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (!mManagesContexts)
	{
		AutoMutex _l(mLock);
		mBinderContextCheckFunc = checkFunc;
		mBinderContextUserData = userData;
		if (mDriverFD >= 0)
		{
			int dummy = 0;
#if defined(HAVE_ANDROID_OS)
			status_t result = ioctl(mDriverFD, BINDER_SET_CONTEXT_MGR, &dummy);
#else
			status_t result = INVALID_OPERATION;
#endif
			if (result == 0) 
			{
				mManagesContexts = true;
			}
			else if (result == -1) 
			{
				mBinderContextCheckFunc = NULL;
				mBinderContextUserData = NULL;
				LOGE("Binder ioctl to become context manager failed: %s\n", strerror(errno));
			}
		}
		else
		{
			// If there is no driver, our only world is the local
			// process so we can always become the context manager there.
			mManagesContexts = true;
		}
	}
	return mManagesContexts;
}

ProcessState::handle_entry* ProcessState::lookupHandleLocked(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、相当于在mHandleToObject  所保存的数组队列中查找，如果数组队列中
			没有，则创建一个并将其添加到此数组队列中
*/
	const size_t N=mHandleToObject.size();
	if (N <= (size_t)handle) 
	{
		handle_entry e;
		e.binder = NULL; /* 指向空*/
		e.refs = NULL;	/* 指向空*/
		status_t err = mHandleToObject.insertAt(e, N, handle+1-N);/* 插入到数组队列中，注意这里插入的单元的内容是空的*/
		if (err < NO_ERROR) 
			return NULL;
	}
	return &mHandleToObject.editItemAt(handle);
}

sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、执行的过程如下:
			A、从mHandleToObject  数组中查找对应的单元
			B、对找到的单元进行相应的添加处理
			C、利用传入的handle  参数new  一个BpBinder  类的实例，此BpBinder  类继承于IBinder  , 所以返回的就是new  的此实例
*/
	sp<IBinder> result;

	AutoMutex _l(mLock);

	handle_entry* e = lookupHandleLocked(handle); /* 从数组中查找对应索引的资源*/

	if (e != NULL) 
	{
		// We need to create a new BpBinder if there isn't currently one, OR we
		// are unable to acquire a weak reference on this current one.  See comment
		// in getWeakProxyForHandle() for more info about this.
		IBinder* b = e->binder;
		if (b == NULL || !e->refs->attemptIncWeak(this)) 
		{
			b = new BpBinder(handle); /* new 一个BpBinder  实例，然后将单元e->binder  设置为刚刚new  的实例*/
			e->binder = b;
			if (b) 
				e->refs = b->getWeakRefs();

			result = b;
		}
		else
		{
			// This little bit of nastyness is to allow us to add a primary
			// reference to the remote proxy when this team doesn't have one
			// but another team is sending the handle to us.
			result.force_set(b);
			e->refs->decWeak(this);
		}
	}

	return result;
}

wp<IBinder> ProcessState::getWeakProxyForHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参见函数getStrongProxyForHandle()  的说明
*/
	wp<IBinder> result;

	AutoMutex _l(mLock);

	handle_entry* e = lookupHandleLocked(handle);

	if (e != NULL)
	{        
		// We need to create a new BpBinder if there isn't currently one, OR we
		// are unable to acquire a weak reference on this current one.  The
		// attemptIncWeak() is safe because we know the BpBinder destructor will always
		// call expungeHandle(), which acquires the same lock we are holding now.
		// We need to do this because there is a race condition between someone
		// releasing a reference on this BpBinder, and a new reference on its handle
		// arriving from the driver.
		IBinder* b = e->binder;
		if (b == NULL || !e->refs->attemptIncWeak(this))
		{
			b = new BpBinder(handle);
			result = b;
			e->binder = b;
			if (b) 
				e->refs = b->getWeakRefs();
		}
		else 
		{
			result = b;
			e->refs->decWeak(this);
		}
	}

	return result;
}

void ProcessState::expungeHandle(int32_t handle, IBinder* binder)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	AutoMutex _l(mLock);

	handle_entry* e = lookupHandleLocked(handle);

	// This handle may have already been replaced with a new BpBinder
	// (if someone failed the AttemptIncWeak() above); we don't want
	// to overwrite it.
	if (e && e->binder == binder) 
		e->binder = NULL;
}

void ProcessState::setArgs(int argc, const char* const argv[])
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mArgC = argc;
	mArgV = (const char **)argv;

	mArgLen = 0;
	for (int i=0; i<argc; i++)
	{
		mArgLen += strlen(argv[i]) + 1;
	}
	mArgLen--;
}

int ProcessState::getArgC() const
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mArgC;
}

const char* const* ProcessState::getArgV() const
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mArgV;
}

void ProcessState::setArgV0(const char* txt)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (mArgV != NULL) 
	{
		strncpy((char*)mArgV[0], txt, mArgLen);
		set_process_name(txt);
	}
}

void ProcessState::spawnPooledThread(bool isMain)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (mThreadPoolStarted)
	{
		int32_t s = android_atomic_add(1, &mThreadPoolSeq);
		char buf[32];
		sprintf(buf, "Binder Thread #%d", s);
		LOGV("Spawning new pooled thread, name=%s\n", buf);
		sp<Thread> t = new PoolThread(isMain); /* ---------ccyykk------->>  启动线程looper  第3  步骤*/
		t->run(buf); /* ---------ccyykk------->>  启动线程looper  第4  步骤*/
	}
}

static int open_driver()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数的功能:
			A、打开binder  驱动，即open("/dev/binder")
			B、调用驱动接口，设定此进程的线程池的线程数量
*/
	if (gSingleProcess) 
	{
		return -1;
	}

	int fd = open("/dev/binder", O_RDWR);
	if (fd >= 0) 
	{
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		int vers;
#if defined(HAVE_ANDROID_OS)
		status_t result = ioctl(fd, BINDER_VERSION, &vers);
#else
		status_t result = -1;
		errno = EPERM;
#endif
		if (result == -1) 
		{
			LOGE("Binder ioctl to obtain version failed: %s", strerror(errno));
			close(fd);
			fd = -1;
		}
		
		if (result != 0 || vers != BINDER_CURRENT_PROTOCOL_VERSION)
		{
			LOGE("Binder driver protocol does not match user space protocol!");
			close(fd);
			fd = -1;
		}
		
#if defined(HAVE_ANDROID_OS)
		size_t maxThreads = 15;
		result = ioctl(fd, BINDER_SET_MAX_THREADS, &maxThreads);
		if (result == -1) 
		{
			LOGE("Binder ioctl to set max threads failed: %s", strerror(errno));
		}
#endif
	}
	else
	{
		LOGW("Opening '/dev/binder' failed: %s\n", strerror(errno));
	}
	
	return fd;
}

ProcessState::ProcessState()
				: mDriverFD(open_driver()) /* 注意此处调用了open_driver  函数*/
				, mVMStart(MAP_FAILED)
				, mManagesContexts(false)
				, mBinderContextCheckFunc(NULL)
				, mBinderContextUserData(NULL)
				, mThreadPoolStarted(false)
				, mThreadPoolSeq(1)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (mDriverFD >= 0) /* binder 驱动已经打开，进行内存映射*/
	{
		// XXX Ideally, there should be a specific define for whether we
		// have mmap (or whether we could possibly have the kernel module
		// availabla).
#if !defined(HAVE_WIN32_IPC)
		// mmap the binder, providing a chunk of virtual address space to receive transactions.
		mVMStart = mmap(0, BINDER_VM_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, mDriverFD, 0);
		if (mVMStart == MAP_FAILED) 
		{
			// *sigh*
			LOGE("Using /dev/binder failed: unable to mmap transaction memory.\n");
			close(mDriverFD);
			mDriverFD = -1;
		}
#else
		mDriverFD = -1;
#endif
	}
	
	if (mDriverFD < 0)
	{
		// Need to run without the driver, starting our own thread pool.
	}
}

ProcessState::~ProcessState()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
}

		
}; // namespace android
