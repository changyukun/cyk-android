/*
 * Copyright (C) 2010 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "ALooper"
#include <utils/Log.h>

#include <sys/time.h>

#include "ALooper.h"

#include "AHandler.h"
#include "ALooperRoster.h"
#include "AMessage.h"

namespace android {

ALooperRoster gLooperRoster;

/*
	Alooper ，它是一个looper  循环，在start  后它启动一个线程不断去检查mEventQueue  队列上是否
	有event事件以及是否达到执行时间，若有，按照如下步骤进行执行:

		1、调用gLooperRoster.deliverMessage(event.mMessage);  对消息进行分发
		2、分发事件消息( 第1  步骤)  从而最终调用handler->onMessageReceived(msg);  来处理消息。

	说明:
		1、第2  步骤中的hander  即调用接口ALooper::registerHandler() 传入的参数
		2、可以通过：void ALooper::post(const sp<AMessage> &msg, int64_t delayUs)  向队列mEventQueue上添加消
			息并唤醒等待的线程去执行上述检查。
		3、event中包含消息，该消息由Amessage表示。
		4、消息处理是AHandler子类完成的，子类实现其纯虚函数onMessageReceived用于处理队
			列上的某个时刻的Amessage消息。

*/

struct ALooper::LooperThread : public Thread 
{
	LooperThread(ALooper *looper, bool canCallJava)
													: Thread(canCallJava),
													mLooper(looper),
													mThreadId(NULL) 
	{
	}

	virtual status_t readyToRun() 
	{
		mThreadId = androidGetThreadId();

		return Thread::readyToRun();
	}

	virtual bool threadLoop() 
	{
		return mLooper->loop();
	}

	bool isCurrentThread() const 
	{
		return mThreadId == androidGetThreadId();
	}

protected:
	virtual ~LooperThread() {}

private:
	ALooper *mLooper;
	android_thread_id_t mThreadId;

	DISALLOW_EVIL_CONSTRUCTORS(LooperThread);
};

// static
int64_t ALooper::GetNowUs() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (int64_t)tv.tv_sec * 1000000ll + tv.tv_usec;
}

ALooper::ALooper() : mRunningLocally(false) 
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

ALooper::~ALooper() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	stop();
}

void ALooper::setName(const char *name)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mName = name;
}

ALooper::handler_id ALooper::registerHandler(const sp<AHandler> &handler) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return gLooperRoster.registerHandler(this, handler);
}

void ALooper::unregisterHandler(handler_id handlerID) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	gLooperRoster.unregisterHandler(handlerID);
}

status_t ALooper::start(bool runOnCallingThread, bool canCallJava, int32_t priority) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (runOnCallingThread) 
	{
		{
			Mutex::Autolock autoLock(mLock);

			if (mThread != NULL || mRunningLocally) 
			{
				return INVALID_OPERATION;
			}

			mRunningLocally = true;
		}

		do
		{
		} while (loop());

		return OK;
	}

	Mutex::Autolock autoLock(mLock);

	if (mThread != NULL || mRunningLocally)
	{
		return INVALID_OPERATION;
	}

	mThread = new LooperThread(this, canCallJava);

	status_t err = mThread->run(mName.empty() ? "ALooper" : mName.c_str(), priority);
	if (err != OK)
	{
		mThread.clear();
	}

	return err;
}

status_t ALooper::stop() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	sp<LooperThread> thread;
	bool runningLocally;

	{
		Mutex::Autolock autoLock(mLock);

		thread = mThread;
		runningLocally = mRunningLocally;
		mThread.clear();
		mRunningLocally = false;
	}

	if (thread == NULL && !runningLocally) 
	{
		return INVALID_OPERATION;
	}

	if (thread != NULL)
	{
		thread->requestExit();
	}

	mQueueChangedCondition.signal();

	if (!runningLocally && !thread->isCurrentThread())
	{
		// If not running locally and this thread _is_ the looper thread,
		// the loop() function will return and never be called again.
		thread->requestExitAndWait();
	}

	return OK;
}

void ALooper::post(const sp<AMessage> &msg, int64_t delayUs) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	Mutex::Autolock autoLock(mLock);

	int64_t whenUs;
	if (delayUs > 0) 
	{
		whenUs = GetNowUs() + delayUs;
	}
	else
	{
		whenUs = GetNowUs();
	}

	List<Event>::iterator it = mEventQueue.begin();
	while (it != mEventQueue.end() && (*it).mWhenUs <= whenUs) 
	{
		++it;
	}

	Event event;
	event.mWhenUs = whenUs;
	event.mMessage = msg;

	if (it == mEventQueue.begin()) 
	{
		mQueueChangedCondition.signal();
	}

	mEventQueue.insert(it, event);
}

bool ALooper::loop() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	Event event;

	{
		Mutex::Autolock autoLock(mLock);
		if (mThread == NULL && !mRunningLocally) 
		{
			return false;
		}
		if (mEventQueue.empty())
		{
			mQueueChangedCondition.wait(mLock);
			return true;
		}
		int64_t whenUs = (*mEventQueue.begin()).mWhenUs;
		int64_t nowUs = GetNowUs();

		if (whenUs > nowUs)
		{
			int64_t delayUs = whenUs - nowUs;
			mQueueChangedCondition.waitRelative(mLock, delayUs * 1000ll);

			return true;
		}

		event = *mEventQueue.begin();
		mEventQueue.erase(mEventQueue.begin());
	}

	gLooperRoster.deliverMessage(event.mMessage);

	// NOTE: It's important to note that at this point our "ALooper" object
	// may no longer exist (its final reference may have gone away while
	// delivering the message). We have made sure, however, that loop()
	// won't be called again.

	return true;
}

}  // namespace android
