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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
}

status_t OMXClient::connect() 
{
/*
	����:
		1��
		
	����:
		1��
		
	˵��:
		1�����ù���:
			1��BpMediaPlayerService -> getOMX()	// 
			2��BnMediaPlayerService -> getOMX()	// 
			3��MediaPlayerService::getOMX() 		// �����ڲ�������һ��BnOMX

			���ع���:
			a�����ù��̵ĵ�3  ���� �����ڲ�������һ��BnOMX  ��ʵ��
			b�����ù��̵ĵ�2  ���� ���´�����BnOMX  ʵ����Ӧ��binder  �ŷ��ظ�BpMediaPlayerService
			c�����ù��̵ĵ�1  ���� ����b  ���践�ص�binder  ��ʵ��һ��BpOMX  ��ʵ������

			����mOMX  ����ֵΪһ��BpOMX  ���͵�ʵ��
			
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
	����:
		1��
		
	����:
		1��
		
	˵��:
		1��
*/
}

}  // namespace android
