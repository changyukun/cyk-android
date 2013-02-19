/*
**
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

// System headers required for setgroups, etc.
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

#include <AudioFlinger.h>
#include <CameraService.h>
#include <MediaPlayerService.h>
#include <AudioPolicyService.h>
#include <private/android_filesystem_config.h>

using namespace android;

int main(int argc, char** argv)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	sp<ProcessState> proc(ProcessState::self());				/* ----> 第1  步,  ProcessState 单例的创建，实现了binder  驱动文件打开等操作*/
	sp<IServiceManager> sm = defaultServiceManager();		/* ----> 第2  步,  获取BpServiceManager  */
	ALOGI("ServiceManager: %p", sm.get());
	AudioFlinger::instantiate();
	MediaPlayerService::instantiate();						/* ----> 第3  步,  添加一个服务，即new MediaPlayerService() */
	CameraService::instantiate();
	AudioPolicyService::instantiate();
	ProcessState::self()->startThreadPool();					/* ----> 第4  步,  创建线程*/
	IPCThreadState::self()->joinThreadPool();					/* ----> 第5  步,  启动线程池 */
}
