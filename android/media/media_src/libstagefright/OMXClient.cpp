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
#define LOG_TAG "OMXClient"
#include <utils/Log.h>

#include <binder/IServiceManager.h>
#include <media/IMediaPlayerService.h>
#include <media/stagefright/MediaDebug.h>
#include <media/stagefright/OMXClient.h>

namespace android {

OMXClient::OMXClient() 
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

status_t OMXClient::connect() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、调用过程:
			1、BpMediaPlayerService -> getOMX()	// 
			2、BnMediaPlayerService -> getOMX()	// 
			3、MediaPlayerService::getOMX() 		// 函数内部创建了一个BnOMX

			返回过程:
			a、调用过程的第3  步骤 函数内部创建了一个BnOMX  的实例
			b、调用过程的第2  步骤 将新创建的BnOMX  实例对应的binder  号返回给BpMediaPlayerService
			c、调用过程的第1  步骤 根据b  步骤返回的binder  号实例一个BpOMX  的实例返回

			所以mOMX  被赋值为一个BpOMX  类型的实例
			
*/
	sp<IServiceManager> sm = defaultServiceManager();
	sp<IBinder> binder = sm->getService(String16("media.player"));
	sp<IMediaPlayerService> service = interface_cast<IMediaPlayerService>(binder);

	CHECK(service.get() != NULL);

	mOMX = service->getOMX();
	CHECK(mOMX.get() != NULL);

	return OK;
}

void OMXClient::disconnect() 
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

}  // namespace android
