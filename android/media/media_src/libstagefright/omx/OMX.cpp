/*
 * Copyright (C) 2009 The Android Open Source Project
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
#define LOG_TAG "OMX"
#include <utils/Log.h>

#include <dlfcn.h>

#include "../include/OMX.h"

#include "../include/OMXNodeInstance.h"

#include <binder/IMemory.h>
#include <media/stagefright/MediaDebug.h>
#include <utils/threads.h>

#include "OMXMaster.h"

#include <OMX_Component.h>

namespace android {

////////////////////////////////////////////////////////////////////////////////

// This provides the underlying Thread used by CallbackDispatcher.
// Note that deriving CallbackDispatcher from Thread does not work.

struct OMX::CallbackDispatcherThread : public Thread 
{
	CallbackDispatcherThread(CallbackDispatcher *dispatcher) 
																:mDispatcher(dispatcher) 
	{
	}

private:
	CallbackDispatcher *mDispatcher;

	bool threadLoop();

	CallbackDispatcherThread(const CallbackDispatcherThread &);
	CallbackDispatcherThread &operator=(const CallbackDispatcherThread &);
};

////////////////////////////////////////////////////////////////////////////////
/*
	参见类OMXNodeInstance  的说明
*/
struct OMX::CallbackDispatcher : public RefBase 
{
	CallbackDispatcher(OMXNodeInstance *owner);

	void post(const omx_message &msg);

	bool loop();

	protected:
	virtual ~CallbackDispatcher();

private:
	Mutex mLock;

	OMXNodeInstance *mOwner; /* 见构造函数对其进行赋值，此值为OMXNodeInstance  的实例*/
	bool mDone;
	Condition mQueueChanged;
	List<omx_message> mQueue;

	sp<CallbackDispatcherThread> mThread;

	void dispatch(const omx_message &msg);

	CallbackDispatcher(const CallbackDispatcher &);
	CallbackDispatcher &operator=(const CallbackDispatcher &);
};

OMX::CallbackDispatcher::CallbackDispatcher(OMXNodeInstance *owner) 
																	: mOwner(owner), 
																	mDone(false) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mThread = new CallbackDispatcherThread(this);
	mThread->run("OMXCallbackDisp", ANDROID_PRIORITY_FOREGROUND);
}

OMX::CallbackDispatcher::~CallbackDispatcher() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	{
		Mutex::Autolock autoLock(mLock);

		mDone = true;
		mQueueChanged.signal();
	}

	// A join on self can happen if the last ref to CallbackDispatcher
	// is released within the CallbackDispatcherThread loop
	status_t status = mThread->join();
	if (status != WOULD_BLOCK) 
	{
		// Other than join to self, the only other error return codes are
		// whatever readyToRun() returns, and we don't override that
		CHECK_EQ(status, NO_ERROR);
	}
}

void OMX::CallbackDispatcher::post(const omx_message &msg) 
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

	mQueue.push_back(msg); 	/* 将消息推入消息队列*/
	mQueueChanged.signal();	/* 发送有消息的信号*/
}

void OMX::CallbackDispatcher::dispatch(const omx_message &msg)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (mOwner == NULL)
	{
		ALOGV("Would have dispatched a message to a node that's already gone.");
		return;
	}
	mOwner->onMessage(msg); /* 调用OMXNodeInstance::onMessage()  方法*/
}

bool OMX::CallbackDispatcher::loop()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、相当于一个组件对应的线程循环
*/
	for (;;) 
	{
		omx_message msg;

		Mutex::Autolock autoLock(mLock);
		while (!mDone && mQueue.empty()) 
		{
			mQueueChanged.wait(mLock);
		}

		if (mDone) 
		{
			break;
		}

		msg = *mQueue.begin(); /* 取出本组件队列中的一条消息*/
		mQueue.erase(mQueue.begin());

		dispatch(msg); /* 分发消息进行处理*/
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////

bool OMX::CallbackDispatcherThread::threadLoop()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return mDispatcher->loop();
}

////////////////////////////////////////////////////////////////////////////////

OMX::OMX()  : mMaster(new OMXMaster), mNodeCounter(0) 
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

OMX::~OMX() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	delete mMaster;
	mMaster = NULL;
}

void OMX::binderDied(const wp<IBinder> &the_late_who)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	OMXNodeInstance *instance;

	{
		Mutex::Autolock autoLock(mLock);

		ssize_t index = mLiveNodes.indexOfKey(the_late_who);
		CHECK(index >= 0);

		instance = mLiveNodes.editValueAt(index);
		mLiveNodes.removeItemsAt(index);

		index = mDispatchers.indexOfKey(instance->nodeID());
		CHECK(index >= 0);
		mDispatchers.removeItemsAt(index);

		invalidateNodeID_l(instance->nodeID());
	}

	instance->onObserverDied(mMaster);
}

bool OMX::livesLocally(pid_t pid) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return pid == getpid();
}

status_t OMX::listNodes(List<ComponentInfo> *list) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	list->clear();

	OMX_U32 index = 0;
	char componentName[256];
	while (mMaster->enumerateComponents(componentName, sizeof(componentName), index) == OMX_ErrorNone) 
	{
		list->push_back(ComponentInfo());
		ComponentInfo &info = *--list->end();

		info.mName = componentName;

		Vector<String8> roles;
		OMX_ERRORTYPE err =
		mMaster->getRolesOfComponent(componentName, &roles);

		if (err == OMX_ErrorNone) 
		{
			for (OMX_U32 i = 0; i < roles.size(); ++i) 
			{
				info.mRoles.push_back(roles[i]);
			}
		}

		++index;
	}

	return OK;
}

status_t OMX::allocateNode(const char *name, const sp<IOMXObserver> &observer, node_id *node)
{
/*
	参数:
		1、name	: 传入一个组件的名字
		2、observer	: 传入一个IOMXObserver  实例指针
		3、node	: 用于返回node  的id
		
	返回:
		1、
		
	说明:
		1、函数执行过程
			a、首先new  一个OMXNodeInstance  的实例
			b、根据传入的组件名字、刚刚new 的OMXNodeInstance  实例来生成一个组件的实例
			c、调用setHandle  将node  的id、组件的handle  设定到OMXNodeInstance  的实例中

		2、注意
			从此函数中的代码分析，每个node 节点即OMXNodeInstance  实例与一个组件对应，从
			代码mMaster->makeComponentInstance()   调用中可知，实例一个组件的时候都是用新实例
			的这个OMXNodeInstance  实例作为参数的
*/
	Mutex::Autolock autoLock(mLock);

	*node = 0;

	OMXNodeInstance *instance = new OMXNodeInstance(this, observer); /* new  一个node  实例*/

	OMX_COMPONENTTYPE *handle;
	
	OMX_ERRORTYPE err = mMaster->makeComponentInstance(name, &OMXNodeInstance::kCallbacks, instance, &handle); /* 实例一个组件，返回组件的handle  */

	if (err != OMX_ErrorNone) 
	{
		ALOGV("FAILED to allocate omx component '%s'", name);

		instance->onGetHandleFailed();

		return UNKNOWN_ERROR;
	}

	*node = makeNodeID(instance); /* 见函数的说明，生成node 实例的id 同时又将id  号与实例对应插入相应的容器*/
	
	mDispatchers.add(*node, new CallbackDispatcher(instance)); /* 向容器中插入id  与callback  实例对应对的数据，见mDispatchers  变量的说明*/

	instance->setHandle(*node, handle); /* 见函数内部代码*/

	mLiveNodes.add(observer->asBinder(), instance); /* 向容器中插入binder  与node  实例对应对的数据，见mLiveNodes  变量的说明*/
	
	observer->asBinder()->linkToDeath(this);

	return OK;
}

status_t OMX::freeNode(node_id node) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	OMXNodeInstance *instance = findInstance(node);

	ssize_t index = mLiveNodes.indexOfKey(instance->observer()->asBinder());
	CHECK(index >= 0);
	mLiveNodes.removeItemsAt(index);

	instance->observer()->asBinder()->unlinkToDeath(this);

	status_t err = instance->freeNode(mMaster);

	{
		Mutex::Autolock autoLock(mLock);
		index = mDispatchers.indexOfKey(node);
		CHECK(index >= 0);
		mDispatchers.removeItemsAt(index);
	}

	return err;
}

status_t OMX::sendCommand(node_id node, OMX_COMMANDTYPE cmd, OMX_S32 param) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看OMX::allocateNode()  方法的说明，因为每个node  实例与一个组件相对应，所以
			此函数最后会调用到相应组件的sendCommand()  方法
*/
	return findInstance(node)->sendCommand(cmd, param);
}

status_t OMX::getParameter(node_id node, OMX_INDEXTYPE index, void *params, size_t size) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看OMX::allocateNode()  方法的说明，因为每个node  实例与一个组件相对应，所以
			此函数最后会调用到相应组件的getParameter()  方法
*/
	return findInstance(node)->getParameter(index, params, size);
}

status_t OMX::setParameter(node_id node, OMX_INDEXTYPE index, const void *params, size_t size) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看OMX::allocateNode()  方法的说明，因为每个node  实例与一个组件相对应，所以
			此函数最后会调用到相应组件的setParameter()  方法
*/
	return findInstance(node)->setParameter(index, params, size);
}

status_t OMX::getConfig(node_id node, OMX_INDEXTYPE index, void *params, size_t size) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看OMX::allocateNode()  方法的说明，因为每个node  实例与一个组件相对应，所以
			此函数最后会调用到相应组件的setParameter()  方法
*/
	return findInstance(node)->getConfig( index, params, size);
}

status_t OMX::setConfig(node_id node, OMX_INDEXTYPE index, const void *params, size_t size)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看OMX::allocateNode()  方法的说明，因为每个node  实例与一个组件相对应，所以
			此函数最后会调用到相应组件的setParameter()  方法
*/
	return findInstance(node)->setConfig( index, params, size);
}

status_t OMX::getState(node_id node, OMX_STATETYPE* state) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看OMX::allocateNode()  方法的说明，因为每个node  实例与一个组件相对应，所以
			此函数最后会调用到相应组件的getState()  方法
*/
	return findInstance(node)->getState(state);
}

status_t OMX::enableGraphicBuffers(node_id node, OMX_U32 port_index, OMX_BOOL enable) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->enableGraphicBuffers(port_index, enable);
}

status_t OMX::getGraphicBufferUsage(node_id node, OMX_U32 port_index, OMX_U32* usage) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->getGraphicBufferUsage(port_index, usage);
}

status_t OMX::storeMetaDataInBuffers(node_id node, OMX_U32 port_index, OMX_BOOL enable) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->storeMetaDataInBuffers(port_index, enable);
}

status_t OMX::useBuffer(node_id node, OMX_U32 port_index, const sp<IMemory> &params, buffer_id *buffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->useBuffer(port_index, params, buffer);
}

status_t OMX::useGraphicBuffer(node_id node, OMX_U32 port_index, const sp<GraphicBuffer> &graphicBuffer, buffer_id *buffer) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->useGraphicBuffer(port_index, graphicBuffer, buffer);
}

status_t OMX::allocateBuffer(node_id node, OMX_U32 port_index, size_t size,buffer_id *buffer, void **buffer_data)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->allocateBuffer(port_index, size, buffer, buffer_data);
}

status_t OMX::allocateBufferWithBackup(node_id node, OMX_U32 port_index, const sp<IMemory> &params,buffer_id *buffer)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->allocateBufferWithBackup( port_index, params, buffer);
}

status_t OMX::freeBuffer(node_id node, OMX_U32 port_index, buffer_id buffer) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->freeBuffer(port_index, buffer);
}

status_t OMX::fillBuffer(node_id node, buffer_id buffer) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->fillBuffer(buffer);
}

status_t OMX::emptyBuffer(node_id node,
						buffer_id buffer,
						OMX_U32 range_offset, 
						OMX_U32 range_length,
						OMX_U32 flags, 
						OMX_TICKS timestamp) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->emptyBuffer(buffer, range_offset, range_length, flags, timestamp);
}

status_t OMX::getExtensionIndex(node_id node,const char *parameter_name,OMX_INDEXTYPE *index) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return findInstance(node)->getExtensionIndex(parameter_name, index);
}

OMX_ERRORTYPE OMX::OnEvent(	node_id node,
								OMX_IN OMX_EVENTTYPE eEvent,
								OMX_IN OMX_U32 nData1,
								OMX_IN OMX_U32 nData2,
								OMX_IN OMX_PTR pEventData) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此方法在OMXNodeInstance::OnEvent()  中被调用
*/
	ALOGV("OnEvent(%d, %ld, %ld)", eEvent, nData1, nData2);

	omx_message msg;
	msg.type = omx_message::EVENT;
	msg.node = node;
	msg.u.event_data.event = eEvent;
	msg.u.event_data.data1 = nData1;
	msg.u.event_data.data2 = nData2;

	findDispatcher(node)->post(msg); /* 调用OMX::CallbackDispatcher::post()  */

	return OMX_ErrorNone;
}

OMX_ERRORTYPE OMX::OnEmptyBufferDone(node_id node, OMX_IN OMX_BUFFERHEADERTYPE *pBuffer) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此方法在OMXNodeInstance::OnEmptyBufferDone()  中被调用
*/
	ALOGV("OnEmptyBufferDone buffer=%p", pBuffer);

	omx_message msg;
	msg.type = omx_message::EMPTY_BUFFER_DONE;
	msg.node = node;
	msg.u.buffer_data.buffer = pBuffer;

	findDispatcher(node)->post(msg); /* 调用OMX::CallbackDispatcher::post()  */

	return OMX_ErrorNone;
}

OMX_ERRORTYPE OMX::OnFillBufferDone(node_id node, OMX_IN OMX_BUFFERHEADERTYPE *pBuffer) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此方法在OMXNodeInstance::OnFillBufferDone()  中被调用
*/
	ALOGV("OnFillBufferDone buffer=%p", pBuffer);

	omx_message msg;
	msg.type = omx_message::FILL_BUFFER_DONE;
	msg.node = node;
	msg.u.extended_buffer_data.buffer = pBuffer;
	msg.u.extended_buffer_data.range_offset = pBuffer->nOffset;
	msg.u.extended_buffer_data.range_length = pBuffer->nFilledLen;
	msg.u.extended_buffer_data.flags = pBuffer->nFlags;
	msg.u.extended_buffer_data.timestamp = pBuffer->nTimeStamp;
	msg.u.extended_buffer_data.platform_private = pBuffer->pPlatformPrivate;
	msg.u.extended_buffer_data.data_ptr = pBuffer->pBuffer;

	findDispatcher(node)->post(msg); /* 调用OMX::CallbackDispatcher::post()  */

	return OMX_ErrorNone;
}

OMX::node_id OMX::makeNodeID(OMXNodeInstance *instance) 
{
/*
	参数:
		1、instance	: 传入一个OMXNodeInstance  的实例
		
	返回:
		1、
		
	说明:
		1、生成一个node 的id  号，全局唯一，然后将这个id  号与传入的实例进行对应后插入到mNodeIDToInstance  对应的容器中
*/
	// mLock is already held.

	node_id node = (node_id)++mNodeCounter;
	mNodeIDToInstance.add(node, instance);

	return node;
}

OMXNodeInstance *OMX::findInstance(node_id node) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、实质就是在容器mNodeIDToInstance  中查找与传入node  对应的那个OMXNodeInstance  实例
*/
	Mutex::Autolock autoLock(mLock);

	ssize_t index = mNodeIDToInstance.indexOfKey(node);

	return index < 0 ? NULL : mNodeIDToInstance.valueAt(index);
}

sp<OMX::CallbackDispatcher> OMX::findDispatcher(node_id node) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、实质就是在容器mDispatchers  中查找与传入node  对应的那个CallbackDispatcher  实例
*/
	Mutex::Autolock autoLock(mLock);

	ssize_t index = mDispatchers.indexOfKey(node);

	return index < 0 ? NULL : mDispatchers.valueAt(index);
}

void OMX::invalidateNodeID(node_id node) 
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
	invalidateNodeID_l(node);
}

void OMX::invalidateNodeID_l(node_id node) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	// mLock is held.
	mNodeIDToInstance.removeItem(node);
}

}  // namespace android
