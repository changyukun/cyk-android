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

#define LOG_TAG "IPCThreadState"

#include <binder/IPCThreadState.h>

#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <cutils/sched_policy.h>
#include <utils/Debug.h>
#include <utils/Log.h>
#include <utils/TextOutput.h>
#include <utils/threads.h>

#include <private/binder/binder_module.h>
#include <private/binder/Static.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#ifdef HAVE_PTHREADS
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#endif
#ifdef HAVE_WIN32_THREADS
#include <windows.h>
#endif


#if LOG_NDEBUG

#define IF_LOG_TRANSACTIONS() if (false)
#define IF_LOG_COMMANDS() if (false)
#define LOG_REMOTEREFS(...) 
#define IF_LOG_REMOTEREFS() if (false)
#define LOG_THREADPOOL(...) 
#define LOG_ONEWAY(...) 

#else

#define IF_LOG_TRANSACTIONS() IF_LOG(LOG_VERBOSE, "transact")
#define IF_LOG_COMMANDS() IF_LOG(LOG_VERBOSE, "ipc")
#define LOG_REMOTEREFS(...) LOG(LOG_DEBUG, "remoterefs", __VA_ARGS__)
#define IF_LOG_REMOTEREFS() IF_LOG(LOG_DEBUG, "remoterefs")
#define LOG_THREADPOOL(...) LOG(LOG_DEBUG, "threadpool", __VA_ARGS__)
#define LOG_ONEWAY(...) LOG(LOG_DEBUG, "ipc", __VA_ARGS__)

#endif

// ---------------------------------------------------------------------------

namespace android {

static const char* getReturnString(size_t idx);
static const char* getCommandString(size_t idx);
static const void* printReturnCommand(TextOutput& out, const void* _cmd);
static const void* printCommand(TextOutput& out, const void* _cmd);

// This will result in a missing symbol failure if the IF_LOG_COMMANDS()
// conditionals don't get stripped...  but that is probably what we want.
#if !LOG_NDEBUG
static const char *kReturnStrings[] = {
#if 1 /* TODO: error update strings */
    "unknown",
#else
    "BR_OK",
    "BR_TIMEOUT",
    "BR_WAKEUP",
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
    "BR_EVENT_OCCURRED",
    "BR_NOOP",
    "BR_SPAWN_LOOPER",
    "BR_FINISHED",
    "BR_DEAD_BINDER",
    "BR_CLEAR_DEATH_NOTIFICATION_DONE"
#endif
};

static const char *kCommandStrings[] = {
#if 1 /* TODO: error update strings */
    "unknown",
#else
    "BC_NOOP",
    "BC_TRANSACTION",
    "BC_REPLY",
    "BC_ACQUIRE_RESULT",
    "BC_FREE_BUFFER",
    "BC_TRANSACTION_COMPLETE",
    "BC_INCREFS",
    "BC_ACQUIRE",
    "BC_RELEASE",
    "BC_DECREFS",
    "BC_INCREFS_DONE",
    "BC_ACQUIRE_DONE",
    "BC_ATTEMPT_ACQUIRE",
    "BC_RETRIEVE_ROOT_OBJECT",
    "BC_SET_THREAD_ENTRY",
    "BC_REGISTER_LOOPER",
    "BC_ENTER_LOOPER",
    "BC_EXIT_LOOPER",
    "BC_SYNC",
    "BC_STOP_PROCESS",
    "BC_STOP_SELF",
    "BC_REQUEST_DEATH_NOTIFICATION",
    "BC_CLEAR_DEATH_NOTIFICATION",
    "BC_DEAD_BINDER_DONE"
#endif
};

static const char* getReturnString(size_t idx)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (idx < sizeof(kReturnStrings) / sizeof(kReturnStrings[0]))
		return kReturnStrings[idx];
	else
		return "unknown";
}

static const char* getCommandString(size_t idx)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (idx < sizeof(kCommandStrings) / sizeof(kCommandStrings[0]))
		return kCommandStrings[idx];
	else
		return "unknown";
}

static const void* printBinderTransactionData(TextOutput& out, const void* data)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	const binder_transaction_data* btd = (const binder_transaction_data*)data;
	out << "target=" << btd->target.ptr << " (cookie " << btd->cookie << ")" << endl
				<< "code=" << TypeCode(btd->code) << ", flags=" << (void*)btd->flags << endl
				<< "data=" << btd->data.ptr.buffer << " (" << (void*)btd->data_size
				<< " bytes)" << endl
				<< "offsets=" << btd->data.ptr.offsets << " (" << (void*)btd->offsets_size
				<< " bytes)" << endl;
	return btd+1;
}

static const void* printReturnCommand(TextOutput& out, const void* _cmd)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	static const int32_t N = sizeof(kReturnStrings)/sizeof(kReturnStrings[0]);

	const int32_t* cmd = (const int32_t*)_cmd;
	int32_t code = *cmd++;
	if (code == BR_ERROR) 
	{
		out << "BR_ERROR: " << (void*)(*cmd++) << endl;
		return cmd;
	} 
	else if (code < 0 || code >= N)
	{
		out << "Unknown reply: " << code << endl;
		return cmd;
	}

	out << kReturnStrings[code];
	
	switch (code) 
	{
		case BR_TRANSACTION:
		case BR_REPLY: 
			{
				out << ": " << indent;
				cmd = (const int32_t *)printBinderTransactionData(out, cmd);
				out << dedent;
			} 
			break;

		case BR_ACQUIRE_RESULT:
			{
				const int32_t res = *cmd++;
				out << ": " << res << (res ? " (SUCCESS)" : " (FAILURE)");
			}
			break;

		case BR_INCREFS:
		case BR_ACQUIRE:
		case BR_RELEASE:
		case BR_DECREFS: 
			{
				const int32_t b = *cmd++;
				const int32_t c = *cmd++;
				out << ": target=" << (void*)b << " (cookie " << (void*)c << ")";
			} 
			break;

		case BR_ATTEMPT_ACQUIRE:
			{
				const int32_t p = *cmd++;
				const int32_t b = *cmd++;
				const int32_t c = *cmd++;
				out << ": target=" << (void*)b << " (cookie " << (void*)c<< "), pri=" << p;
			} 
			break;

		case BR_DEAD_BINDER:
		case BR_CLEAR_DEATH_NOTIFICATION_DONE: 
			{
				const int32_t c = *cmd++;
				out << ": death cookie " << (void*)c;
			} 
			break;
	}

	out << endl;
	return cmd;
}

static const void* printCommand(TextOutput& out, const void* _cmd)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	static const int32_t N = sizeof(kCommandStrings)/sizeof(kCommandStrings[0]);

	const int32_t* cmd = (const int32_t*)_cmd;
	int32_t code = *cmd++;
	
	if (code < 0 || code >= N) 
	{
		out << "Unknown command: " << code << endl;
		return cmd;
	}

	out << kCommandStrings[code];
	switch (code) 
	{
		case BC_TRANSACTION:
		case BC_REPLY: 
			{
				out << ": " << indent;
				cmd = (const int32_t *)printBinderTransactionData(out, cmd);
				out << dedent;
			} 
			break;

		case BC_ACQUIRE_RESULT: 
			{
				const int32_t res = *cmd++;
				out << ": " << res << (res ? " (SUCCESS)" : " (FAILURE)");
			} 
			break;

		case BC_FREE_BUFFER: 
			{
				const int32_t buf = *cmd++;
				out << ": buffer=" << (void*)buf;
			} 
			break;

		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS: 
			{
				const int32_t d = *cmd++;
				out << ": descriptor=" << (void*)d;
			} 
			break;

		case BC_INCREFS_DONE:
		case BC_ACQUIRE_DONE: 
			{
				const int32_t b = *cmd++;
				const int32_t c = *cmd++;
				out << ": target=" << (void*)b << " (cookie " << (void*)c << ")";
			} 
			break;

		case BC_ATTEMPT_ACQUIRE: 
			{
				const int32_t p = *cmd++;
				const int32_t d = *cmd++;
				out << ": decriptor=" << (void*)d << ", pri=" << p;
			} 
			break;

		case BC_REQUEST_DEATH_NOTIFICATION:
		case BC_CLEAR_DEATH_NOTIFICATION: 
			{
				const int32_t h = *cmd++;
				const int32_t c = *cmd++;
				out << ": handle=" << h << " (death cookie " << (void*)c << ")";
			}
			break;

		case BC_DEAD_BINDER_DONE: 
			{
				const int32_t c = *cmd++;
				out << ": death cookie " << (void*)c;
			}
			break;
	}

	out << endl;
	return cmd;
}
#endif

static pthread_mutex_t gTLSMutex = PTHREAD_MUTEX_INITIALIZER;
static bool gHaveTLS = false;
static pthread_key_t gTLS = 0;
static bool gShutdown = false;
static bool gDisableBackgroundScheduling = false;

/*
	线程存储说明: ==========> 
	
	下面说一下线程中特有的线程存储， Thread Specific Data 。线程存储有什么用了？他是什么意思了？大
	家都知道，在多线程程序中，所有线程共享程序中的变量。现在有一全局变量，所有线程都可以
	使用它，改变它的值。而如果每个线程希望能单独拥有它，那么就需要使用线程存储了。表面上
	看起来这是一个全局变量，所有线程都可以使用它，而它的值在每一个线程中又是单独存储的。
	这就是线程存储的意义。

	下面说一下线程存储的具体用法
	
	1、创建一个类型为 pthread_key_t 类型的变量。
	2、调用 pthread_key_create() 来创建该变量。该函数有两个参数，第一个参数就是上面声明的 pthread_key_t 变
		量，第二个参数是一个清理函数，用来在线程释放该线程存储的时候被调用。该函数指针可以
		设成 NULL ，这样系统将调用默认的清理函数。
	3、当线程中需要存储特殊值的时候，可以调用 pthread_setspcific() 。该函数有两个参数，第一个为前面声
		明的 pthread_key_t 变量，第二个为 void* 变量，这样你可以存储任何类型的值。
	4、如果需要取出所存储的值，调用 pthread_getspecific() 。该函数的参数为前面提到的 pthread_key_t 变量，该
		函数返回 void * 类型的值。
*/

IPCThreadState* IPCThreadState::self()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、对此函数的理解可参看上面的说明
*/
	if (gHaveTLS) 
	{
restart:
		const pthread_key_t k = gTLS;
		IPCThreadState* st = (IPCThreadState*)pthread_getspecific(k);
		if (st) 
			return st;
		return new IPCThreadState;
	}

	if (gShutdown) 
		return NULL;

	pthread_mutex_lock(&gTLSMutex);
	if (!gHaveTLS) 
	{
		if (pthread_key_create(&gTLS, threadDestructor) != 0) /* 创建一个线程存储的变量*/
		{
			pthread_mutex_unlock(&gTLSMutex);
			return NULL;
		}
		gHaveTLS = true;
	}
	pthread_mutex_unlock(&gTLSMutex);
	goto restart;
}

void IPCThreadState::shutdown()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	gShutdown = true;

	if (gHaveTLS) 
	{
		// XXX Need to wait for all thread pool threads to exit!
		IPCThreadState* st = (IPCThreadState*)pthread_getspecific(gTLS);
		if (st)
		{
			delete st;
			pthread_setspecific(gTLS, NULL);
		}
		gHaveTLS = false;
	}
}

void IPCThreadState::disableBackgroundScheduling(bool disable)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	gDisableBackgroundScheduling = disable;
}

sp<ProcessState> IPCThreadState::process()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mProcess;
}

status_t IPCThreadState::clearLastError()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	const status_t err = mLastError;
	mLastError = NO_ERROR;
	return err;
}

int IPCThreadState::getCallingPid()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mCallingPid;
}

int IPCThreadState::getCallingUid()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mCallingUid;
}

int64_t IPCThreadState::clearCallingIdentity()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	int64_t token = ((int64_t)mCallingUid<<32) | mCallingPid;
	clearCaller();
	return token;
}

void IPCThreadState::setStrictModePolicy(int32_t policy)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	mStrictModePolicy = policy;
}

int32_t IPCThreadState::getStrictModePolicy() const
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mStrictModePolicy;
}

void IPCThreadState::setLastTransactionBinderFlags(int32_t flags)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	mLastTransactionBinderFlags = flags;
}

int32_t IPCThreadState::getLastTransactionBinderFlags() const
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mLastTransactionBinderFlags;
}

void IPCThreadState::restoreCallingIdentity(int64_t token)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mCallingUid = (int)(token>>32);
	mCallingPid = (int)token;
}

void IPCThreadState::clearCaller()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mCallingPid = getpid();
	mCallingUid = getuid();
}

void IPCThreadState::flushCommands()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (mProcess->mDriverFD <= 0)
		return;
	talkWithDriver(false);
}

void IPCThreadState::joinThreadPool(bool isMain)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	LOG_THREADPOOL("**** THREAD %p (PID %d) IS JOINING THE THREAD POOL\n", (void*)pthread_self(), getpid());

	mOut.writeInt32(isMain ? BC_ENTER_LOOPER : BC_REGISTER_LOOPER);

	// This thread may have been spawned by a thread that was in the background
	// scheduling group, so first we will make sure it is in the default/foreground
	// one to avoid performing an initial transaction in the background.
	androidSetThreadSchedulingGroup(mMyThreadId, ANDROID_TGROUP_DEFAULT);

	status_t result;
	do /* 线程的循环*/
	{
		int32_t cmd;

		// When we've cleared the incoming command queue, process any pending derefs
		if (mIn.dataPosition() >= mIn.dataSize()) 
		{
			size_t numPending = mPendingWeakDerefs.size();
			if (numPending > 0) 
			{
				for (size_t i = 0; i < numPending; i++) 
				{
					RefBase::weakref_type* refs = mPendingWeakDerefs[i];
					refs->decWeak(mProcess.get());
				}
				mPendingWeakDerefs.clear();
			}

			numPending = mPendingStrongDerefs.size();
			if (numPending > 0) 
			{
				for (size_t i = 0; i < numPending; i++)
				{
					BBinder* obj = mPendingStrongDerefs[i];
					obj->decStrong(mProcess.get());
				}
				mPendingStrongDerefs.clear();
			}
		}

		// now get the next command to be processed, waiting if necessary
		result = talkWithDriver();
		
		if (result >= NO_ERROR)
		{
			size_t IN = mIn.dataAvail();
			if (IN < sizeof(int32_t)) 
				continue;
			
			cmd = mIn.readInt32();
			IF_LOG_COMMANDS() 
			{
				alog << "Processing top-level Command: "<< getReturnString(cmd) << endl;
			}

			result = executeCommand(cmd);
		}

		// After executing the command, ensure that the thread is returned to the
		// default cgroup before rejoining the pool.  The driver takes care of
		// restoring the priority, but doesn't do anything with cgroups so we
		// need to take care of that here in userspace.  Note that we do make
		// sure to go in the foreground after executing a transaction, but
		// there are other callbacks into user code that could have changed
		// our group so we want to make absolutely sure it is put back.
		androidSetThreadSchedulingGroup(mMyThreadId, ANDROID_TGROUP_DEFAULT);

		// Let this thread exit the thread pool if it is no longer
		// needed and it is not the main process thread.
		if(result == TIMED_OUT && !isMain) 
		{
			break;
		}
	} while (result != -ECONNREFUSED && result != -EBADF);

	LOG_THREADPOOL("**** THREAD %p (PID %d) IS LEAVING THE THREAD POOL err=%p\n",(void*)pthread_self(), getpid(), (void*)result);

	mOut.writeInt32(BC_EXIT_LOOPER);
	talkWithDriver(false);
}

void IPCThreadState::stopProcess(bool immediate)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	//LOGI("**** STOPPING PROCESS");
	flushCommands();
	int fd = mProcess->mDriverFD;
	mProcess->mDriverFD = -1;
	close(fd);
	//kill(getpid(), SIGKILL);
}

status_t IPCThreadState::transact(int32_t handle, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	status_t err = data.errorCheck();

	flags |= TF_ACCEPT_FDS;

	IF_LOG_TRANSACTIONS() 
	{
		TextOutput::Bundle _b(alog);
		alog << "BC_TRANSACTION thr " << (void*)pthread_self() << " / hand " << handle << " / code " << TypeCode(code) << ": " << indent << data << dedent << endl;
	}

	if (err == NO_ERROR)
	{
		LOG_ONEWAY(">>>> SEND from pid %d uid %d %s", getpid(), getuid(),(flags & TF_ONE_WAY) == 0 ? "READ REPLY" : "ONE WAY");
		err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, NULL); /* 见函数说明，实现对要写出数据的封装*/
	}

	if (err != NO_ERROR) 
	{
		if (reply)
			reply->setError(err);
		return (mLastError = err);
	}

	if ((flags & TF_ONE_WAY) == 0) 
	{
#if 0
		if (code == 4) 
		{ // relayout
			LOGI(">>>>>> CALLING transaction 4");
		} 
		else
		{
			LOGI(">>>>>> CALLING transaction %d", code);
		}
#endif
		if (reply) 
		{
			err = waitForResponse(reply); /* 见函数说明，调用驱动binder  将数据写出*/
		}
		else
		{
			Parcel fakeReply;
			err = waitForResponse(&fakeReply); /* 见函数说明，调用驱动binder  将数据写出*/
		}
#if 0
		if (code == 4) 
		{ // relayout
			LOGI("<<<<<< RETURNING transaction 4");
		} 
		else
		{
			LOGI("<<<<<< RETURNING transaction %d", code);
		}
#endif

		IF_LOG_TRANSACTIONS() 
		{
			TextOutput::Bundle _b(alog);
			alog << "BR_REPLY thr " << (void*)pthread_self() << " / hand "<< handle << ": ";
			if (reply) 
				alog << indent << *reply << dedent << endl;
			else
				alog << "(none requested)" << endl;
		}
	}
	else 
	{
		err = waitForResponse(NULL, NULL); /* 见函数说明，调用驱动binder  将数据写出*/
	}

	return err;
}

void IPCThreadState::incStrongHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	LOG_REMOTEREFS("IPCThreadState::incStrongHandle(%d)\n", handle);
	mOut.writeInt32(BC_ACQUIRE);
	mOut.writeInt32(handle);
}

void IPCThreadState::decStrongHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	LOG_REMOTEREFS("IPCThreadState::decStrongHandle(%d)\n", handle);
	mOut.writeInt32(BC_RELEASE);
	mOut.writeInt32(handle);
}

void IPCThreadState::incWeakHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	LOG_REMOTEREFS("IPCThreadState::incWeakHandle(%d)\n", handle);
	mOut.writeInt32(BC_INCREFS);
	mOut.writeInt32(handle);
}

void IPCThreadState::decWeakHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	LOG_REMOTEREFS("IPCThreadState::decWeakHandle(%d)\n", handle);
	mOut.writeInt32(BC_DECREFS);
	mOut.writeInt32(handle);
}

status_t IPCThreadState::attemptIncStrongHandle(int32_t handle)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mOut.writeInt32(BC_ATTEMPT_ACQUIRE);
	mOut.writeInt32(0); // xxx was thread priority
	mOut.writeInt32(handle);
	status_t result = UNKNOWN_ERROR;

	waitForResponse(NULL, &result);

#if LOG_REFCOUNTS
	printf("IPCThreadState::attemptIncStrongHandle(%ld) = %s\n",handle, result == NO_ERROR ? "SUCCESS" : "FAILURE");
#endif

	return result;
}

void IPCThreadState::expungeHandle(int32_t handle, IBinder* binder)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
#if LOG_REFCOUNTS
	printf("IPCThreadState::expungeHandle(%ld)\n", handle);
#endif
	self()->mProcess->expungeHandle(handle, binder);
}

status_t IPCThreadState::requestDeathNotification(int32_t handle, BpBinder* proxy)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mOut.writeInt32(BC_REQUEST_DEATH_NOTIFICATION);
	mOut.writeInt32((int32_t)handle);
	mOut.writeInt32((int32_t)proxy);
	return NO_ERROR;
}

status_t IPCThreadState::clearDeathNotification(int32_t handle, BpBinder* proxy)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mOut.writeInt32(BC_CLEAR_DEATH_NOTIFICATION);
	mOut.writeInt32((int32_t)handle);
	mOut.writeInt32((int32_t)proxy);
	return NO_ERROR;
}

IPCThreadState::IPCThreadState() : 	mProcess(ProcessState::self()), /* 注意此处调用了ProcessState::self() */
									mMyThreadId(androidGetTid()),
									mStrictModePolicy(0),
									mLastTransactionBinderFlags(0)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	pthread_setspecific(gTLS, this); /* 见文件上面对线程存储的说明*/
	clearCaller();
	mIn.setDataCapacity(256); /* 设置mIn , mIn 相当于命令的buffer */
	mOut.setDataCapacity(256);/* 设置mOut , mOut 相当于命令的buffer */
} 

IPCThreadState::~IPCThreadState()
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

status_t IPCThreadState::sendReply(const Parcel& reply, uint32_t flags)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	status_t err;
	status_t statusBuffer;
	err = writeTransactionData(BC_REPLY, flags, -1, 0, reply, &statusBuffer);
	if (err < NO_ERROR) 
		return err;

	return waitForResponse(NULL, NULL);
}

status_t IPCThreadState::waitForResponse(Parcel *reply, status_t *acquireResult)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、调用talkWithDriver()  函数使用binder  驱动进行数据真正写出
*/
	int32_t cmd;
	int32_t err;

	while (1) 
	{
		if ((err=talkWithDriver()) < NO_ERROR) 
			break;
		
		err = mIn.errorCheck();
		if (err < NO_ERROR)
			break;
		
		if (mIn.dataAvail() == 0) 
			continue;

		cmd = mIn.readInt32();

		IF_LOG_COMMANDS() 
		{
			alog << "Processing waitForResponse Command: "<< getReturnString(cmd) << endl;
		}

		switch (cmd) 
		{
			case BR_TRANSACTION_COMPLETE:
				if (!reply && !acquireResult) 
					goto finish;
				break;

			case BR_DEAD_REPLY:
				err = DEAD_OBJECT;
				goto finish;

			case BR_FAILED_REPLY:
				err = FAILED_TRANSACTION;
				goto finish;

			case BR_ACQUIRE_RESULT:
				{
					LOG_ASSERT(acquireResult != NULL, "Unexpected brACQUIRE_RESULT");
					const int32_t result = mIn.readInt32();
					if (!acquireResult)
						continue;
					*acquireResult = result ? NO_ERROR : INVALID_OPERATION;
				}
				goto finish;

			case BR_REPLY:
				{
					binder_transaction_data tr;
					err = mIn.read(&tr, sizeof(tr));
					LOG_ASSERT(err == NO_ERROR, "Not enough command data for brREPLY");
					if (err != NO_ERROR) 
						goto finish;

					if (reply)
					{
						if ((tr.flags & TF_STATUS_CODE) == 0) 
						{
							reply->ipcSetDataReference(	reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
														tr.data_size,
														reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
														tr.offsets_size/sizeof(size_t),
														freeBuffer, this);
						} 
						else
						{
							err = *static_cast<const status_t*>(tr.data.ptr.buffer);
							freeBuffer(NULL,
									reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
									tr.data_size,
									reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
									tr.offsets_size/sizeof(size_t), this);
						}
					}
					else
					{
						freeBuffer(NULL,
						reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
						tr.data_size,
						reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
						tr.offsets_size/sizeof(size_t), this);
						continue;
					}
				}
				goto finish;

			default:
				err = executeCommand(cmd);
				if (err != NO_ERROR)
					goto finish;
				break;
		}
	}

finish:
	if (err != NO_ERROR)
	{
		if (acquireResult) 
			*acquireResult = err;
		if (reply) 
			reply->setError(err);
		mLastError = err;
	}

	return err;
}

status_t IPCThreadState::talkWithDriver(bool doReceive)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数真正的调用了驱动进行数据的读写
*/
	LOG_ASSERT(mProcess->mDriverFD >= 0, "Binder driver is not opened");

	binder_write_read bwr;

	// Is the read buffer empty?
	const bool needRead = mIn.dataPosition() >= mIn.dataSize();

	// We don't want to write anything if we are still reading
	// from data left in the input buffer and the caller
	// has requested to read the next data.
	const size_t outAvail = (!doReceive || needRead) ? mOut.dataSize() : 0;

	bwr.write_size = outAvail;
	bwr.write_buffer = (long unsigned int)mOut.data();

	// This is what we'll read.
	if (doReceive && needRead) 
	{
		bwr.read_size = mIn.dataCapacity();
		bwr.read_buffer = (long unsigned int)mIn.data();
	} 
	else
	{
		bwr.read_size = 0;
	}

	IF_LOG_COMMANDS()
	{
		TextOutput::Bundle _b(alog);
		if (outAvail != 0) 
		{
			alog << "Sending commands to driver: " << indent;
			const void* cmds = (const void*)bwr.write_buffer;
			const void* end = ((const uint8_t*)cmds)+bwr.write_size;
			alog << HexDump(cmds, bwr.write_size) << endl;
			while (cmds < end) 
				cmds = printCommand(alog, cmds);
			alog << dedent;
		}
		alog << "Size of receive buffer: " << bwr.read_size<< ", needRead: " << needRead << ", doReceive: " << doReceive << endl;
	}

	// Return immediately if there is nothing to do.
	if ((bwr.write_size == 0) && (bwr.read_size == 0)) 
		return NO_ERROR;

	bwr.write_consumed = 0;
	bwr.read_consumed = 0;
	status_t err;
	do 
	{
		IF_LOG_COMMANDS()
		{
			alog << "About to read/write, write size = " << mOut.dataSize() << endl;
		}
#if defined(HAVE_ANDROID_OS)
		if (ioctl(mProcess->mDriverFD, BINDER_WRITE_READ, &bwr) >= 0) /* binder  驱动真正的数据写入*/
			err = NO_ERROR;
		else
			err = -errno;
#else
		err = INVALID_OPERATION;
#endif
		IF_LOG_COMMANDS() 
		{
			alog << "Finished read/write, write size = " << mOut.dataSize() << endl;
		}
	} while (err == -EINTR);

	IF_LOG_COMMANDS() 
	{
		alog << "Our err: " << (void*)err << ", write consumed: "<< bwr.write_consumed << " (of " << mOut.dataSize()<< "), read consumed: " << bwr.read_consumed << endl;
	}

	if (err >= NO_ERROR) 
	{
		if (bwr.write_consumed > 0) 
		{
			if (bwr.write_consumed < (ssize_t)mOut.dataSize())
				mOut.remove(0, bwr.write_consumed);
			else
				mOut.setDataSize(0);
		}
		
		if (bwr.read_consumed > 0)
		{
			mIn.setDataSize(bwr.read_consumed);
			mIn.setDataPosition(0);
		}
		
		IF_LOG_COMMANDS()
		{
			TextOutput::Bundle _b(alog);
			alog << "Remaining data size: " << mOut.dataSize() << endl;
			alog << "Received commands from driver: " << indent;
			const void* cmds = mIn.data();
			const void* end = mIn.data() + mIn.dataSize();
			alog << HexDump(cmds, mIn.dataSize()) << endl;
			while (cmds < end) 
				cmds = printReturnCommand(alog, cmds);
			alog << dedent;
		}
		return NO_ERROR;
	}

	return err;
}

status_t IPCThreadState::writeTransactionData(int32_t cmd, uint32_t binderFlags, int32_t handle, uint32_t code, const Parcel& data, status_t* statusBuffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数实现了对数据的封装，即将数据封装成binder_transaction_data  类型的数据结构，然后
			将数据写入到mOut  中，是一个类，相当于命令的缓冲区，并没有真正的调用驱动binder
			将数据写出去，调用驱动binder  执行写的动作是在方法waitForResponse  完成的
*/
	binder_transaction_data tr;

	tr.target.handle = handle;
	tr.code = code;
	tr.flags = binderFlags;

	const status_t err = data.errorCheck();
	if (err == NO_ERROR) 
	{
		tr.data_size = data.ipcDataSize();
		tr.data.ptr.buffer = data.ipcData();
		tr.offsets_size = data.ipcObjectsCount()*sizeof(size_t);
		tr.data.ptr.offsets = data.ipcObjects();
	}
	else if (statusBuffer)
	{
		tr.flags |= TF_STATUS_CODE;
		*statusBuffer = err;
		tr.data_size = sizeof(status_t);
		tr.data.ptr.buffer = statusBuffer;
		tr.offsets_size = 0;
		tr.data.ptr.offsets = NULL;
	} 
	else
	{
		return (mLastError = err);
	}

	mOut.writeInt32(cmd);
	mOut.write(&tr, sizeof(tr));

	return NO_ERROR;
}

sp<BBinder> the_context_object;

void setTheContextObject(sp<BBinder> obj)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	the_context_object = obj;
}

status_t IPCThreadState::executeCommand(int32_t cmd)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	BBinder* obj;
	RefBase::weakref_type* refs;
	status_t result = NO_ERROR;

	switch (cmd)
	{
		case BR_ERROR:
			result = mIn.readInt32();
			break;

		case BR_OK:
			break;

		case BR_ACQUIRE:
			refs = (RefBase::weakref_type*)mIn.readInt32();
			obj = (BBinder*)mIn.readInt32();
			LOG_ASSERT(refs->refBase() == obj,"BR_ACQUIRE: object %p does not match cookie %p (expected %p)",refs, obj, refs->refBase());
			obj->incStrong(mProcess.get());
			IF_LOG_REMOTEREFS() 
			{
				LOG_REMOTEREFS("BR_ACQUIRE from driver on %p", obj);
				obj->printRefs();
			}
			mOut.writeInt32(BC_ACQUIRE_DONE);
			mOut.writeInt32((int32_t)refs);
			mOut.writeInt32((int32_t)obj);
			break;

		case BR_RELEASE:
			refs = (RefBase::weakref_type*)mIn.readInt32();
			obj = (BBinder*)mIn.readInt32();
			LOG_ASSERT(refs->refBase() == obj,"BR_RELEASE: object %p does not match cookie %p (expected %p)",refs, obj, refs->refBase());
			IF_LOG_REMOTEREFS()
			{
				LOG_REMOTEREFS("BR_RELEASE from driver on %p", obj);
				obj->printRefs();
			}
			mPendingStrongDerefs.push(obj);
			break;

		case BR_INCREFS:
			refs = (RefBase::weakref_type*)mIn.readInt32();
			obj = (BBinder*)mIn.readInt32();
			refs->incWeak(mProcess.get());
			mOut.writeInt32(BC_INCREFS_DONE);
			mOut.writeInt32((int32_t)refs);
			mOut.writeInt32((int32_t)obj);
			break;

		case BR_DECREFS:
			refs = (RefBase::weakref_type*)mIn.readInt32();
			obj = (BBinder*)mIn.readInt32();
			// NOTE: This assertion is not valid, because the object may no
			// longer exist (thus the (BBinder*)cast above resulting in a different
			// memory address).
			//LOG_ASSERT(refs->refBase() == obj,
			//           "BR_DECREFS: object %p does not match cookie %p (expected %p)",
			//           refs, obj, refs->refBase());
			mPendingWeakDerefs.push(refs);
			break;

		case BR_ATTEMPT_ACQUIRE:
			refs = (RefBase::weakref_type*)mIn.readInt32();
			obj = (BBinder*)mIn.readInt32();
			{
				const bool success = refs->attemptIncStrong(mProcess.get());
				LOG_ASSERT(success && refs->refBase() == obj,"BR_ATTEMPT_ACQUIRE: object %p does not match cookie %p (expected %p)",refs, obj, refs->refBase());

				mOut.writeInt32(BC_ACQUIRE_RESULT);
				mOut.writeInt32((int32_t)success);
			}
			break;

		case BR_TRANSACTION:
			{
				binder_transaction_data tr;
				result = mIn.read(&tr, sizeof(tr));
				LOG_ASSERT(result == NO_ERROR,
				"Not enough command data for brTRANSACTION");
				
				if (result != NO_ERROR) 
					break;

				Parcel buffer;
				buffer.ipcSetDataReference(	reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
										tr.data_size,
										reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
										tr.offsets_size/sizeof(size_t), freeBuffer, this);

				const pid_t origPid = mCallingPid;
				const uid_t origUid = mCallingUid;

				mCallingPid = tr.sender_pid;
				mCallingUid = tr.sender_euid;

				int curPrio = getpriority(PRIO_PROCESS, mMyThreadId);
				if (gDisableBackgroundScheduling) 
				{
					if (curPrio > ANDROID_PRIORITY_NORMAL) 
					{
						// We have inherited a reduced priority from the caller, but do not
						// want to run in that state in this process.  The driver set our
						// priority already (though not our scheduling class), so bounce
						// it back to the default before invoking the transaction.
						setpriority(PRIO_PROCESS, mMyThreadId, ANDROID_PRIORITY_NORMAL);
					}
				} 
				else
				{
					if (curPrio >= ANDROID_PRIORITY_BACKGROUND) 
					{
						// We want to use the inherited priority from the caller.
						// Ensure this thread is in the background scheduling class,
						// since the driver won't modify scheduling classes for us.
						// The scheduling group is reset to default by the caller
						// once this method returns after the transaction is complete.
						androidSetThreadSchedulingGroup(mMyThreadId,ANDROID_TGROUP_BG_NONINTERACT);
					}
				}

				//LOGI(">>>> TRANSACT from pid %d uid %d\n", mCallingPid, mCallingUid);

				Parcel reply;
				IF_LOG_TRANSACTIONS() 
				{
					TextOutput::Bundle _b(alog);
					alog << "BR_TRANSACTION thr " << (void*)pthread_self()<< " / obj " << tr.target.ptr << " / code "<< TypeCode(tr.code) << ": " << indent << buffer<< dedent << endl<< "Data addr = "<< reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer)<< ", offsets addr="<< reinterpret_cast<const size_t*>(tr.data.ptr.offsets) << endl;
				}
				
				if (tr.target.ptr) 
				{
					sp<BBinder> b((BBinder*)tr.cookie);
					const status_t error = b->transact(tr.code, buffer, &reply, tr.flags);
					if (error < NO_ERROR) 
						reply.setError(error);
				} 
				else 
				{
					const status_t error = the_context_object->transact(tr.code, buffer, &reply, tr.flags);
					if (error < NO_ERROR)
						reply.setError(error);
				}

				//LOGI("<<<< TRANSACT from pid %d restore pid %d uid %d\n",
				//     mCallingPid, origPid, origUid);

				if ((tr.flags & TF_ONE_WAY) == 0) 
				{
					LOG_ONEWAY("Sending reply to %d!", mCallingPid);
					sendReply(reply, 0);
				} 
				else
				{
					LOG_ONEWAY("NOT sending reply to %d!", mCallingPid);
				}

				mCallingPid = origPid;
				mCallingUid = origUid;

				IF_LOG_TRANSACTIONS() 
				{
					TextOutput::Bundle _b(alog);
					alog << "BC_REPLY thr " << (void*)pthread_self() << " / obj " << tr.target.ptr << ": " << indent << reply << dedent << endl;
				}

			}
			break;

		case BR_DEAD_BINDER:
			{
				BpBinder *proxy = (BpBinder*)mIn.readInt32();
				proxy->sendObituary();
				mOut.writeInt32(BC_DEAD_BINDER_DONE);
				mOut.writeInt32((int32_t)proxy);
			} 
			break;

		case BR_CLEAR_DEATH_NOTIFICATION_DONE:
			{
				BpBinder *proxy = (BpBinder*)mIn.readInt32();
				proxy->getWeakRefs()->decWeak(proxy);
			} 
			break;

		case BR_FINISHED:
			result = TIMED_OUT;
			break;

		case BR_NOOP:
			break;

		case BR_SPAWN_LOOPER:
			mProcess->spawnPooledThread(false);
			break;

		default:
			printf("*** BAD COMMAND %d received from Binder driver\n", cmd);
			result = UNKNOWN_ERROR;
			break;
	}

	if (result != NO_ERROR)
	{
		mLastError = result;
	}

	return result;
}

void IPCThreadState::threadDestructor(void *st)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	IPCThreadState* const self = static_cast<IPCThreadState*>(st);
	if (self) 
	{
		self->flushCommands();
#if defined(HAVE_ANDROID_OS)
		ioctl(self->mProcess->mDriverFD, BINDER_THREAD_EXIT, 0);
#endif
		delete self;
	}
}


void IPCThreadState::freeBuffer(Parcel* parcel, const uint8_t* data, size_t dataSize, const size_t* objects, size_t objectsSize, void* cookie)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	//LOGI("Freeing parcel %p", &parcel);
	IF_LOG_COMMANDS()
	{
		alog << "Writing BC_FREE_BUFFER for " << data << endl;
	}
	LOG_ASSERT(data != NULL, "Called with NULL data");
	if (parcel != NULL) 
		parcel->closeFileDescriptors();
	IPCThreadState* state = self();
	state->mOut.writeInt32(BC_FREE_BUFFER);
	state->mOut.writeInt32((int32_t)data);
}

}; // namespace android
