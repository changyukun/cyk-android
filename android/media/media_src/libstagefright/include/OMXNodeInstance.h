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

#ifndef OMX_NODE_INSTANCE_H_

#define OMX_NODE_INSTANCE_H_

#include "OMX.h"

#include <utils/RefBase.h>
#include <utils/threads.h>

namespace android {

class IOMXObserver;
struct OMXMaster;

/*
	此类的作用可参看OMX::allocateNode()  方法的说明

	此数据结构OMXNodeInstance 相当于在omx  标准组件定义的基础上又封装了一层，即相当于以omx  组件标准
	为基类实现的此结构，所谓相当于是因为此为一个数据结构，而omx  组件标准也是一个数据结构，
	那么如何实现的此关系继承就是在此数据结构中定义一个成员变量OMX_HANDLETYPE mHandle; 实质mHandle 就会
	被赋值一个OMX_COMPONENTTYPE  类型的实例

	因此调用此实例的很多方法就是通过域成员mHandle  调用的真正组件的方法，有些则是此数据结构自己
	的方法
*/
struct OMXNodeInstance 
{
	OMXNodeInstance(OMX *owner, const sp<IOMXObserver> &observer);

	void setHandle(OMX::node_id node_id, OMX_HANDLETYPE handle);

	OMX *owner();
	sp<IOMXObserver> observer();
	OMX::node_id nodeID();

	status_t freeNode(OMXMaster *master);

	status_t sendCommand(OMX_COMMANDTYPE cmd, OMX_S32 param);
	status_t getParameter(OMX_INDEXTYPE index, void *params, size_t size);

	status_t setParameter(OMX_INDEXTYPE index, const void *params, size_t size);

	status_t getConfig(OMX_INDEXTYPE index, void *params, size_t size);
	status_t setConfig(OMX_INDEXTYPE index, const void *params, size_t size);

	status_t getState(OMX_STATETYPE* state);

	status_t enableGraphicBuffers(OMX_U32 portIndex, OMX_BOOL enable);

	status_t getGraphicBufferUsage(OMX_U32 portIndex, OMX_U32* usage);

	status_t storeMetaDataInBuffers(OMX_U32 portIndex, OMX_BOOL enable);

	status_t useBuffer(OMX_U32 portIndex, const sp<IMemory> &params, OMX::buffer_id *buffer);

	status_t useGraphicBuffer(OMX_U32 portIndex, const sp<GraphicBuffer> &graphicBuffer, OMX::buffer_id *buffer);

	status_t allocateBuffer(OMX_U32 portIndex, size_t size, OMX::buffer_id *buffer, void **buffer_data);

	status_t allocateBufferWithBackup(OMX_U32 portIndex, const sp<IMemory> &params, OMX::buffer_id *buffer);

	status_t freeBuffer(OMX_U32 portIndex, OMX::buffer_id buffer);

	status_t fillBuffer(OMX::buffer_id buffer);

	status_t emptyBuffer(OMX::buffer_id buffer, OMX_U32 rangeOffset, OMX_U32 rangeLength, OMX_U32 flags, OMX_TICKS timestamp);

	status_t getExtensionIndex(const char *parameterName, OMX_INDEXTYPE *index);

	void onMessage(const omx_message &msg);
	void onObserverDied(OMXMaster *master);
	void onGetHandleFailed();

	static OMX_CALLBACKTYPE kCallbacks;

private:
	Mutex mLock;

	OMX * mOwner; /* 此值为BnOMX  的实例，即在MediaPlayerService::getOMX()  方法中new  出来的*/
	OMX::node_id mNodeID; /* 见方法OMX::allocateNode  中调用OMXNodeInstance::setHandle  方法对其进行的设定*/
	OMX_HANDLETYPE mHandle;/* 此值为一个组件的句柄，见方法OMX::allocateNode  中调用OMXNodeInstance::setHandle  方法对其进行的设定*/
	sp<IOMXObserver> mObserver;
	bool mDying;

	struct ActiveBuffer 
	{
		OMX_U32 mPortIndex;
		OMX::buffer_id mID;
	};
	Vector<ActiveBuffer> mActiveBuffers;

	~OMXNodeInstance();

	void addActiveBuffer(OMX_U32 portIndex, OMX::buffer_id id);
	void removeActiveBuffer(OMX_U32 portIndex, OMX::buffer_id id);
	void freeActiveBuffers();
	
	status_t useGraphicBuffer2_l(OMX_U32 portIndex, 
									const sp<GraphicBuffer> &graphicBuffer,
									OMX::buffer_id *buffer);
	
	static OMX_ERRORTYPE OnEvent(OMX_IN OMX_HANDLETYPE hComponent,
									OMX_IN OMX_PTR pAppData,
									OMX_IN OMX_EVENTTYPE eEvent,
									OMX_IN OMX_U32 nData1,
									OMX_IN OMX_U32 nData2,
									OMX_IN OMX_PTR pEventData);

	static OMX_ERRORTYPE OnEmptyBufferDone(OMX_IN OMX_HANDLETYPE hComponent,
												OMX_IN OMX_PTR pAppData,
												OMX_IN OMX_BUFFERHEADERTYPE *pBuffer);

	static OMX_ERRORTYPE OnFillBufferDone(OMX_IN OMX_HANDLETYPE hComponent,
											OMX_IN OMX_PTR pAppData,
											OMX_IN OMX_BUFFERHEADERTYPE *pBuffer);

	OMXNodeInstance(const OMXNodeInstance &);
	OMXNodeInstance &operator=(const OMXNodeInstance &);
};

}  // namespace android

#endif  // OMX_NODE_INSTANCE_H_
