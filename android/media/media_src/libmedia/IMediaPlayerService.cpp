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

#include <stdint.h>
#include <sys/types.h>

#include <binder/Parcel.h>
#include <binder/IMemory.h>
#include <media/IMediaPlayerService.h>
#include <media/IMediaRecorder.h>
#include <media/IOMX.h>
#include <media/IStreamSource.h>

#include <utils/Errors.h>  // for status_t

namespace android {

enum 
{
	CREATE = IBinder::FIRST_CALL_TRANSACTION,
	DECODE_URL,
	DECODE_FD,
	CREATE_MEDIA_RECORDER,
	CREATE_METADATA_RETRIEVER,
	GET_OMX,
	ADD_BATTERY_DATA,
	PULL_BATTERY_DATA
};

class BpMediaPlayerService: public BpInterface<IMediaPlayerService>
{
public:
	BpMediaPlayerService(const sp<IBinder>& impl) : BpInterface<IMediaPlayerService>(impl)
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

	virtual sp<IMediaMetadataRetriever> createMetadataRetriever(pid_t pid)
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		data.writeInt32(pid);
		remote()->transact(CREATE_METADATA_RETRIEVER, data, &reply);
		return interface_cast<IMediaMetadataRetriever>(reply.readStrongBinder());
	}

	virtual sp<IMediaPlayer> create( pid_t pid, const sp<IMediaPlayerClient>& client, int audioSessionId)
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		data.writeInt32(pid);
		data.writeStrongBinder(client->asBinder()); /* 将BnMediaPlayerClient  实例的binder 引用号传递给服务端*/
		data.writeInt32(audioSessionId);

		remote()->transact(CREATE, data, &reply);
		return interface_cast<IMediaPlayer>(reply.readStrongBinder());
	}

	virtual sp<IMediaRecorder> createMediaRecorder(pid_t pid)
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		data.writeInt32(pid);
		remote()->transact(CREATE_MEDIA_RECORDER, data, &reply);
		return interface_cast<IMediaRecorder>(reply.readStrongBinder());
	}

	virtual sp<IMemory> decode(const char* url, uint32_t *pSampleRate, int* pNumChannels, int* pFormat)
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		data.writeCString(url);
		remote()->transact(DECODE_URL, data, &reply);
		*pSampleRate = uint32_t(reply.readInt32());
		*pNumChannels = reply.readInt32();
		*pFormat = reply.readInt32();
		return interface_cast<IMemory>(reply.readStrongBinder());
	}

	virtual sp<IMemory> decode(int fd, int64_t offset, int64_t length, uint32_t *pSampleRate, int* pNumChannels, int* pFormat)
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		data.writeFileDescriptor(fd);
		data.writeInt64(offset);
		data.writeInt64(length);
		remote()->transact(DECODE_FD, data, &reply);
		*pSampleRate = uint32_t(reply.readInt32());
		*pNumChannels = reply.readInt32();
		*pFormat = reply.readInt32();
		return interface_cast<IMemory>(reply.readStrongBinder());
	}

	virtual sp<IOMX> getOMX() 
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		remote()->transact(GET_OMX, data, &reply);
		return interface_cast<IOMX>(reply.readStrongBinder());
	}

	virtual void addBatteryData(uint32_t params)
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
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		data.writeInt32(params);
		remote()->transact(ADD_BATTERY_DATA, data, &reply);
	}

	virtual status_t pullBatteryData(Parcel* reply)
	{
	/*
		参数:
			1、
			
		返回:
			1、
			
		说明:
			1、
	*/
		Parcel data;
		data.writeInterfaceToken(IMediaPlayerService::getInterfaceDescriptor());
		return remote()->transact(PULL_BATTERY_DATA, data, reply);
	}
};

/* IMediaPlayerService::asInterface()  等接口实现*/
IMPLEMENT_META_INTERFACE(MediaPlayerService, "android.media.IMediaPlayerService");

// ----------------------------------------------------------------------

status_t BnMediaPlayerService::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、此函数为BnMediaPlayerService  的onTransact  方法，即应该为主线程的Looper   调用的函数，所以
			多媒体的本地服务端，即BnMediaPlayerService  通过此方法接收代理即BpMediaPlayerService  发送
			过来的命令

			接收到命令后会对相应命令进行处理，然后再将相应返回返回

			此函数中调用的方法多数为MediaPlayerService  类的方法，因为MediaPlayerService  类是继承BnMediaPlayerService
			类的，如函数中调用create  函数，就应该是MediaPlayerService::create
*/
	switch(code)
	{
		case CREATE: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				pid_t pid = data.readInt32();
				sp<IMediaPlayerClient> client = interface_cast<IMediaPlayerClient>(data.readStrongBinder()); /* 取出BnMediaPlayerClient  实例的binder 引用号，构建服务端的BpMediaPlayerClient  实例*/
				int audioSessionId = data.readInt32();
				sp<IMediaPlayer> player = create(pid, client, audioSessionId); /* 见MediaPlayerService::create()  方法*/
				reply->writeStrongBinder(player->asBinder());
				return NO_ERROR;
			} 
			break;

		case DECODE_URL: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				const char* url = data.readCString();
				uint32_t sampleRate;
				int numChannels;
				int format;
				sp<IMemory> player = decode(url, &sampleRate, &numChannels, &format);
				reply->writeInt32(sampleRate);
				reply->writeInt32(numChannels);
				reply->writeInt32(format);
				reply->writeStrongBinder(player->asBinder());
				return NO_ERROR;
			} 
			break;

		case DECODE_FD: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				int fd = dup(data.readFileDescriptor());
				int64_t offset = data.readInt64();
				int64_t length = data.readInt64();
				uint32_t sampleRate;
				int numChannels;
				int format;
				sp<IMemory> player = decode(fd, offset, length, &sampleRate, &numChannels, &format); /* 见MediaPlayerService::decode()  方法*/
				reply->writeInt32(sampleRate);
				reply->writeInt32(numChannels);
				reply->writeInt32(format);
				reply->writeStrongBinder(player->asBinder());
				return NO_ERROR;
			}
			break;

		case CREATE_MEDIA_RECORDER:
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				pid_t pid = data.readInt32();
				sp<IMediaRecorder> recorder = createMediaRecorder(pid);
				reply->writeStrongBinder(recorder->asBinder());
				return NO_ERROR;
			} 
			break;

		case CREATE_METADATA_RETRIEVER: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				pid_t pid = data.readInt32();
				sp<IMediaMetadataRetriever> retriever = createMetadataRetriever(pid);
				reply->writeStrongBinder(retriever->asBinder());
				return NO_ERROR;
			} 
			break;

		case GET_OMX: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				sp<IOMX> omx = getOMX();
				reply->writeStrongBinder(omx->asBinder());
				return NO_ERROR;
			} 
			break;

		case ADD_BATTERY_DATA: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				uint32_t params = data.readInt32();
				addBatteryData(params);
				return NO_ERROR;
			} 
			break;

		case PULL_BATTERY_DATA: 
			{
				CHECK_INTERFACE(IMediaPlayerService, data, reply);
				pullBatteryData(reply);
				return NO_ERROR;
			} 
			break;

		default:
			return BBinder::onTransact(code, data, reply, flags);
	}
}

// ----------------------------------------------------------------------------

}; // namespace android
