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
#define LOG_TAG "StagefrightPlayer"
#include <utils/Log.h>

#include "StagefrightPlayer.h"

#include "AwesomePlayer.h"

#include <media/Metadata.h>
#include <media/stagefright/MediaExtractor.h>

namespace android {

StagefrightPlayer::StagefrightPlayer() : mPlayer(new AwesomePlayer) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("StagefrightPlayer");

	mPlayer->setListener(this);
}

StagefrightPlayer::~StagefrightPlayer() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("~StagefrightPlayer");
	reset();

	delete mPlayer;
	mPlayer = NULL;
}

status_t StagefrightPlayer::initCheck()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("initCheck");
	return OK;
}

status_t StagefrightPlayer::setUID(uid_t uid) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	mPlayer->setUID(uid);

	return OK;
}

status_t StagefrightPlayer::setDataSource( const char *url, const KeyedVector<String8, String8> *headers) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return mPlayer->setDataSource(url, headers);
}

// Warning: The filedescriptor passed into this method will only be valid until
// the method returns, if you want to keep it, dup it!
status_t StagefrightPlayer::setDataSource(int fd, int64_t offset, int64_t length) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("setDataSource(%d, %lld, %lld)", fd, offset, length);
	return mPlayer->setDataSource(dup(fd), offset, length);
}

status_t StagefrightPlayer::setDataSource(const sp<IStreamSource> &source)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return mPlayer->setDataSource(source);
}

status_t StagefrightPlayer::setVideoSurfaceTexture( const sp<ISurfaceTexture> &surfaceTexture) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("setVideoSurfaceTexture");

	return mPlayer->setSurfaceTexture(surfaceTexture);
}

status_t StagefrightPlayer::prepare() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return mPlayer->prepare();
}

status_t StagefrightPlayer::prepareAsync() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return mPlayer->prepareAsync();
}

status_t StagefrightPlayer::start() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("start");

	return mPlayer->play();
}

status_t StagefrightPlayer::stop()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("stop");

	return pause();  // what's the difference?
}

status_t StagefrightPlayer::pause() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("pause");

	return mPlayer->pause();
}

bool StagefrightPlayer::isPlaying()
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("isPlaying");
	return mPlayer->isPlaying();
}

status_t StagefrightPlayer::seekTo(int msec) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("seekTo %.2f secs", msec / 1E3);

	status_t err = mPlayer->seekTo((int64_t)msec * 1000);

	return err;
}

status_t StagefrightPlayer::getCurrentPosition(int *msec) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("getCurrentPosition");

	int64_t positionUs;
	status_t err = mPlayer->getPosition(&positionUs);

	if (err != OK) 
	{
		return err;
	}

	*msec = (positionUs + 500) / 1000;

	return OK;
}

status_t StagefrightPlayer::getDuration(int *msec) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("getDuration");

	int64_t durationUs;
	status_t err = mPlayer->getDuration(&durationUs);

	if (err != OK) 
	{
		*msec = 0;
		return OK;
	}

	*msec = (durationUs + 500) / 1000;

	return OK;
}

status_t StagefrightPlayer::reset() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("reset");

	mPlayer->reset();

	return OK;
}

status_t StagefrightPlayer::setLooping(int loop) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("setLooping");

	return mPlayer->setLooping(loop);
}

player_type StagefrightPlayer::playerType() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("playerType");
	return STAGEFRIGHT_PLAYER;
}

status_t StagefrightPlayer::invoke(const Parcel &request, Parcel *reply) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return INVALID_OPERATION;
}

void StagefrightPlayer::setAudioSink(const sp<AudioSink> &audioSink) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	MediaPlayerInterface::setAudioSink(audioSink);

	mPlayer->setAudioSink(audioSink);
}

status_t StagefrightPlayer::setParameter(int key, const Parcel &request)
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("setParameter");
	return mPlayer->setParameter(key, request);
}

status_t StagefrightPlayer::getParameter(int key, Parcel *reply) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	ALOGV("getParameter");
	return mPlayer->getParameter(key, reply);
}

status_t StagefrightPlayer::getMetadata( const media::Metadata::Filter& ids, Parcel *records) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	using media::Metadata;

	uint32_t flags = mPlayer->flags();

	Metadata metadata(records);

	metadata.appendBool(Metadata::kPauseAvailable, flags & MediaExtractor::CAN_PAUSE);

	metadata.appendBool(Metadata::kSeekBackwardAvailable, flags & MediaExtractor::CAN_SEEK_BACKWARD);

	metadata.appendBool(Metadata::kSeekForwardAvailable,flags & MediaExtractor::CAN_SEEK_FORWARD);

	metadata.appendBool(Metadata::kSeekAvailable, flags & MediaExtractor::CAN_SEEK);

	return OK;
}

status_t StagefrightPlayer::dump(int fd, const Vector<String16> &args) const 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	return mPlayer->dump(fd, args);
}

}  // namespace android
