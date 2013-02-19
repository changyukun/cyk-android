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

#define LOG_TAG "ServiceManager"

#include <binder/IServiceManager.h>

#include <utils/Debug.h>
#include <utils/Log.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <utils/String8.h>
#include <utils/SystemClock.h>

#include <private/binder/Static.h>

#include <unistd.h>

namespace android {

sp<IServiceManager> defaultServiceManager()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	if (gDefaultServiceManager != NULL) 
		return gDefaultServiceManager;

	{
		AutoMutex _l(gDefaultServiceManagerLock);
		if (gDefaultServiceManager == NULL) 
		{
			/* 
				如何将BpBinder* 转换为IServiceManager*  的，请看宏 interface_cast  定义

				下面的代码等价于:

				sp<IServiceManager> interface_cast (const sp<BpBinder>& obj)
				{
					return IServiceManager::asInterface ( obj );
				}

				gDefaultServiceManager = interface_cast ( ProcessState::self()->getContextObject(NULL) );
				
			*/
			gDefaultServiceManager = interface_cast<IServiceManager>(ProcessState::self()->getContextObject(NULL)); /* 相当于调用ProcessState::getContextObject()  方法*/

			/*
				由于(ProcessState::self()->getContextObject(NULL)  返回的就是new BpBinder(0)  ，所以最后相当于:

				gDefaultServiceManager = interface_cast<IServiceManager>( new BpBinder(0) );  ===> 又等价于:
				gDefaultServiceManager = IServiceManager::asInterface ( new BpBinder(0) );

				而方法IServiceManager::asInterface()  见宏实现IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager");
			*/
		}
	}

	return gDefaultServiceManager;
}

bool checkCallingPermission(const String16& permission)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
    	return checkCallingPermission(permission, NULL, NULL);
}

static String16 _permission("permission");


bool checkCallingPermission(const String16& permission, int32_t* outPid, int32_t* outUid)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	IPCThreadState* ipcState = IPCThreadState::self();
	pid_t pid = ipcState->getCallingPid();
	uid_t uid = ipcState->getCallingUid();
	if (outPid) 
		*outPid = pid;
	
	if (outUid)
		*outUid = uid;
	
	return checkPermission(permission, pid, uid);
}

bool checkPermission(const String16& permission, pid_t pid, uid_t uid)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	sp<IPermissionController> pc;
	gDefaultServiceManagerLock.lock();
	pc = gPermissionController;
	gDefaultServiceManagerLock.unlock();

	int64_t startTime = 0;

	while (true)
	{
		if (pc != NULL)
		{
			bool res = pc->checkPermission(permission, pid, uid);
			if (res) 
			{
				if (startTime != 0) 
				{
					LOGI("Check passed after %d seconds for %s from uid=%d pid=%d",(int)((uptimeMillis()-startTime)/1000),String8(permission).string(), uid, pid);
				}
				return res;
			}

			// Is this a permission failure, or did the controller go away?
			if (pc->asBinder()->isBinderAlive()) 
			{
				LOGW("Permission failure: %s from uid=%d pid=%d",String8(permission).string(), uid, pid);
				return false;
			}

			// Object is dead!
			gDefaultServiceManagerLock.lock();
			
			if (gPermissionController == pc) 
			{
				gPermissionController = NULL;
			}
			gDefaultServiceManagerLock.unlock();
		}

		// Need to retrieve the permission controller.
		sp<IBinder> binder = defaultServiceManager()->checkService(_permission);
		if (binder == NULL) 
		{
			// Wait for the permission controller to come back...
			if (startTime == 0) 
			{
				startTime = uptimeMillis();
				LOGI("Waiting to check permission %s from uid=%d pid=%d",String8(permission).string(), uid, pid);
			}
			sleep(1);
		}
		else
		{
			pc = interface_cast<IPermissionController>(binder);
			// Install the new permission controller, and try again.        
			gDefaultServiceManagerLock.lock();
			gPermissionController = pc;
			gDefaultServiceManagerLock.unlock();
		}
	}
}

// ----------------------------------------------------------------------

/*
	BpServicManager 中的Bp  等价于Binder Proxy
*/
class BpServiceManager : public BpInterface<IServiceManager>
{
public:
	BpServiceManager(const sp<IBinder>& impl) : BpInterface<IServiceManager>(impl)
	{
	}

	virtual sp<IBinder> getService(const String16& name) const
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
		for (n = 0; n < 5; n++)
		{
			sp<IBinder> svc = checkService(name);
			if (svc != NULL) 
				return svc;
			LOGI("Waiting for service %s...\n", String8(name).string());
			sleep(1);
		}
		return NULL;
	}

	virtual sp<IBinder> checkService( const String16& name) const
	{
	/*
		参数:
			1、
			
		返回:
			1、
			
		说明:
			1、
	*/
		Parcel data, reply;
		data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
		data.writeString16(name);
		remote()->transact(CHECK_SERVICE_TRANSACTION, data, &reply);
		return reply.readStrongBinder();
	}

	virtual status_t addService(const String16& name, const sp<IBinder>& service)
	{
	/*
		参数:
			1、
			
		返回:
			1、
			
		说明:
			1、
	*/
		Parcel data, reply; /* data 是发送到BnServiceManager  的命令包*/

		/* 下面代码相当于将命令写入*/
		data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());/* 先把interface  名字写进去，也就是什么android.os.IServiceManager  */
		data.writeString16(name); /* 再把新的service  名字写进去*/
		data.writeStrongBinder(service); /* 新的service  写进去*/

		/* 调用remote  的transact  接口*/
		status_t err = remote()->transact(ADD_SERVICE_TRANSACTION, data, &reply);
		
		return err == NO_ERROR ? reply.readExceptionCode() : err;
	}

	virtual Vector<String16> listServices()
	{
	/*
		参数:
			1、
			
		返回:
			1、
			
		说明:
			1、
	*/
		Vector<String16> res;
		int n = 0;

		for (;;) 
		{
			Parcel data, reply;
			data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
			data.writeInt32(n++);
			status_t err = remote()->transact(LIST_SERVICES_TRANSACTION, data, &reply);
			if (err != NO_ERROR)
				break;
			res.add(reply.readString16());
		}
		return res;
	}
};

IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager"); /* 详见此宏的定义，挺复杂的，相当于在此处添加了很多代码*/

// ----------------------------------------------------------------------

status_t BnServiceManager::onTransact( uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	//printf("ServiceManager received: "); data.print();
	switch(code) 
	{
		case GET_SERVICE_TRANSACTION:
			{
				CHECK_INTERFACE(IServiceManager, data, reply);
				String16 which = data.readString16();
				sp<IBinder> b = const_cast<BnServiceManager*>(this)->getService(which);
				reply->writeStrongBinder(b);
				return NO_ERROR;
			} 
			break;
			
		case CHECK_SERVICE_TRANSACTION:
			{
				CHECK_INTERFACE(IServiceManager, data, reply);
				String16 which = data.readString16();
				sp<IBinder> b = const_cast<BnServiceManager*>(this)->checkService(which);
				reply->writeStrongBinder(b);
				return NO_ERROR;
			} 
			break;
			
		case ADD_SERVICE_TRANSACTION:
			{
				CHECK_INTERFACE(IServiceManager, data, reply);
				String16 which = data.readString16();
				sp<IBinder> b = data.readStrongBinder();
				status_t err = addService(which, b);
				reply->writeInt32(err);
				return NO_ERROR;
			} 
			break;
			
		case LIST_SERVICES_TRANSACTION:
			{
				CHECK_INTERFACE(IServiceManager, data, reply);
				Vector<String16> list = listServices();
				const size_t N = list.size();
				reply->writeInt32(N);
				for (size_t i=0; i<N; i++) 
				{
					reply->writeString16(list[i]);
				}
				return NO_ERROR;
			} break;
		
		default:
			return BBinder::onTransact(code, data, reply, flags);
	}
}

}; // namespace android
