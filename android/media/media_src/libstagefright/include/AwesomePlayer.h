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

#ifndef AWESOME_PLAYER_H_

#define AWESOME_PLAYER_H_

#include "HTTPBase.h"
#include "TimedEventQueue.h"

#include <media/MediaPlayerInterface.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/OMXClient.h>
#include <media/stagefright/TimeSource.h>
#include <utils/threads.h>
#include <drm/DrmManagerClient.h>

namespace android {

struct AudioPlayer;
struct DataSource;
struct MediaBuffer;
struct MediaExtractor;
struct MediaSource;
struct NuCachedSource2;
struct ISurfaceTexture;

class DrmManagerClinet;
class DecryptHandle;

class TimedTextPlayer;
struct WVMExtractor;

/* AwesomePlayer 播放器的渲染器类的基类*/
struct AwesomeRenderer : public RefBase 
{
	AwesomeRenderer() {}

	virtual void render(MediaBuffer *buffer) = 0;

private:
	AwesomeRenderer(const AwesomeRenderer &);
	AwesomeRenderer &operator=(const AwesomeRenderer &);
};

struct AwesomePlayer 
{
	AwesomePlayer();
	~AwesomePlayer();

	void setListener(const wp<MediaPlayerBase> &listener);
	void setUID(uid_t uid);

	status_t setDataSource(const char *uri, const KeyedVector<String8, String8> *headers = NULL);

	status_t setDataSource(int fd, int64_t offset, int64_t length);

	status_t setDataSource(const sp<IStreamSource> &source);

	void reset();

	status_t prepare();
	status_t prepare_l();
	status_t prepareAsync();
	status_t prepareAsync_l();

	status_t play();
	status_t pause();

	bool isPlaying() const;

	status_t setSurfaceTexture(const sp<ISurfaceTexture> &surfaceTexture);
	void setAudioSink(const sp<MediaPlayerBase::AudioSink> &audioSink);
	status_t setLooping(bool shouldLoop);

	status_t getDuration(int64_t *durationUs);
	status_t getPosition(int64_t *positionUs);

	status_t setParameter(int key, const Parcel &request);
	status_t getParameter(int key, Parcel *reply);
	status_t setCacheStatCollectFreq(const Parcel &request);

	status_t seekTo(int64_t timeUs);

	// This is a mask of MediaExtractor::Flags.
	uint32_t flags() const;

	void postAudioEOS(int64_t delayUs = 0ll);
	void postAudioSeekComplete();

	status_t setTimedTextTrackIndex(int32_t index);

	status_t dump(int fd, const Vector<String16> &args) const;

private:
	friend struct AwesomeEvent;
	friend struct PreviewPlayer;

	enum 
	{
		PLAYING             = 0x01,
		LOOPING             = 0x02,
		FIRST_FRAME         = 0x04,
		PREPARING           = 0x08,
		PREPARED            = 0x10,
		AT_EOS              = 0x20,
		PREPARE_CANCELLED   = 0x40,
		CACHE_UNDERRUN      = 0x80,
		AUDIO_AT_EOS        = 0x0100,
		VIDEO_AT_EOS        = 0x0200,
		AUTO_LOOPING        = 0x0400,

		// We are basically done preparing but are currently buffering
		// sufficient data to begin playback and finish the preparation phase
		// for good.
		PREPARING_CONNECTED = 0x0800,

		// We're triggering a single video event to display the first frame
		// after the seekpoint.
		SEEK_PREVIEW        = 0x1000,

		AUDIO_RUNNING       = 0x2000,
		AUDIOPLAYER_STARTED = 0x4000,

		INCOGNITO           = 0x8000,

		TEXT_RUNNING        = 0x10000,
		TEXTPLAYER_STARTED  = 0x20000,

		SLOW_DECODER_HACK   = 0x40000,
	};

	mutable Mutex mLock;
	Mutex mMiscStateLock;
	mutable Mutex mStatsLock;
	Mutex mAudioLock;

	OMXClient mClient; /* 见构造函数AwesomePlayer::AwesomePlayer()  调用了此实例的connect  方法，然后对此实例的mOMX  域成员进行了赋值，即mOMX 为OMX 的代理BpOMX  的实例*/
	TimedEventQueue mQueue; /* 见AwesomePlayer::prepareAsync_l() 方法对start 的调用，从而创建了event  线程*/
	bool mQueueStarted;
	wp<MediaPlayerBase> mListener; /* 见StagefrightPlayer::StagefrightPlayer()  方法对其进行的赋值，实质就是一个StagefrightPlayer  的实例*/
	bool mUIDValid;
	uid_t mUID;

	sp<ANativeWindow> mNativeWindow;
	sp<MediaPlayerBase::AudioSink> mAudioSink;

	SystemTimeSource mSystemTimeSource;
	TimeSource *mTimeSource;

	String8 mUri; /* 见方法AwesomePlayer::setDataSource_l  中对其进行的赋值*/
	KeyedVector<String8, String8> mUriHeaders;

	sp<DataSource> mFileSource;

	sp<MediaSource> mVideoTrack; /* 见方法AwesomePlayer::setDataSource_l 中调用AwesomePlayer::setVideoSource  对其进行设定*/
	sp<MediaSource> mVideoSource; /* 见方法AwesomePlayer::initVideoDecoder 对其进行赋值、见方法AwesomePlayer::onPrepareAsyncEvent()  中的说明*/
	sp<AwesomeRenderer> mVideoRenderer; /* 见AwesomePlayer::initRenderer_l() 方法对其进行的赋值*/
	bool mVideoRendererIsPreview;

	sp<MediaSource> mAudioTrack; /* 见方法AwesomePlayer::setDataSource_l 中调用AwesomePlayer::setAudioSource  对其进行设定*/
	sp<MediaSource> mAudioSource; /* 见方法AwesomePlayer::initAudioDecoder  对其进行赋值*/
	AudioPlayer *mAudioPlayer;
	int64_t mDurationUs;

	int32_t mDisplayWidth; /* 见方法AwesomePlayer::setDataSource_l  对其赋值*/
	int32_t mDisplayHeight; /* 见方法AwesomePlayer::setDataSource_l  对其赋值*/

	uint32_t mFlags;
	uint32_t mExtractorFlags;
	uint32_t mSinceLastDropped;

	int64_t mTimeSourceDeltaUs;
	int64_t mVideoTimeUs;

	enum SeekType 
	{
		NO_SEEK,
		SEEK,
		SEEK_VIDEO_ONLY
	};
	SeekType mSeeking;

	bool mSeekNotificationSent;
	int64_t mSeekTimeUs;

	int64_t mBitrate;  // total bitrate of the file (in bps) or -1 if unknown.

	bool mWatchForAudioSeekComplete;
	bool mWatchForAudioEOS;

	sp<TimedEventQueue::Event> mVideoEvent; /* 见构造函数的创建，通过函数postVideoEvent_l() 调用发送此事件，然后事件线程TimedEventQueue::threadEntry()  就会处理此事件，就会调用此事件的处理函数AwesomePlayer::onVideoEvent() */
	bool mVideoEventPending; /* 此变量用于防止onVideoEvent() 或者onVideoEvent()  函数被连续的两次调用，目的就是确保这两个函数交替一对一的顺序调用*/
	sp<TimedEventQueue::Event> mStreamDoneEvent;
	bool mStreamDoneEventPending; /* 参看mVideoEventPending 成员的说明，目的都是防止添加事件函数或者响应事件函数被连续的两次调用，确保添加函数与响应函数一对一的顺序调用 */
	sp<TimedEventQueue::Event> mBufferingEvent;
	bool mBufferingEventPending; /* 参看mVideoEventPending 成员的说明，目的都是防止添加事件函数或者响应事件函数被连续的两次调用，确保添加函数与响应函数一对一的顺序调用 */
	sp<TimedEventQueue::Event> mCheckAudioStatusEvent;
	bool mAudioStatusEventPending; /* 参看mVideoEventPending 成员的说明，目的都是防止添加事件函数或者响应事件函数被连续的两次调用，确保添加函数与响应函数一对一的顺序调用 */
	sp<TimedEventQueue::Event> mVideoLagEvent;
	bool mVideoLagEventPending; /* 参看mVideoEventPending 成员的说明，目的都是防止添加事件函数或者响应事件函数被连续的两次调用，确保添加函数与响应函数一对一的顺序调用 */

	sp<TimedEventQueue::Event> mAsyncPrepareEvent; /* 见AwesomePlayer::prepareAsync_l() 方法创建的此变量，此事件的处理函数为AwesomePlayer::onPrepareAsyncEvent() ，参看上面mVideoEvent 事件的说明*/
	Condition mPreparedCondition;
	bool mIsAsyncPrepare;
	status_t mPrepareResult;
	status_t mStreamDoneStatus;

	void postVideoEvent_l(int64_t delayUs = -1);
	void postBufferingEvent_l();
	void postStreamDoneEvent_l(status_t status);
	void postCheckAudioStatusEvent(int64_t delayUs);
	void postVideoLagEvent_l();
	status_t play_l();

	MediaBuffer *mVideoBuffer;

	sp<HTTPBase> mConnectingDataSource;
	sp<NuCachedSource2> mCachedSource;

	DrmManagerClient *mDrmManagerClient;
	sp<DecryptHandle> mDecryptHandle;

	int64_t mLastVideoTimeUs;
	TimedTextPlayer *mTextPlayer;
	mutable Mutex mTimedTextLock;

	sp<WVMExtractor> mWVMExtractor;

	status_t setDataSource_l(
	const char *uri,
	const KeyedVector<String8, String8> *headers = NULL);

	status_t setDataSource_l(const sp<DataSource> &dataSource);
	status_t setDataSource_l(const sp<MediaExtractor> &extractor);
	void reset_l();
	status_t seekTo_l(int64_t timeUs);
	status_t pause_l(bool at_eos = false);
	void initRenderer_l();
	void notifyVideoSize_l();
	void seekAudioIfNecessary_l();

	void cancelPlayerEvents(bool keepNotifications = false);

	void setAudioSource(sp<MediaSource> source);
	status_t initAudioDecoder();

	void setVideoSource(sp<MediaSource> source);
	status_t initVideoDecoder(uint32_t flags = 0);

	void addTextSource(sp<MediaSource> source);

	void onStreamDone();

	void notifyListener_l(int msg, int ext1 = 0, int ext2 = 0);

	void onVideoEvent();
	void onBufferingUpdate();
	void onCheckAudioStatus();
	void onPrepareAsyncEvent();
	void abortPrepare(status_t err);
	void finishAsyncPrepare_l();
	void onVideoLagUpdate();

	bool getCachedDuration_l(int64_t *durationUs, bool *eos);

	status_t finishSetDataSource_l();

	static bool ContinuePreparation(void *cookie);

	bool getBitrate(int64_t *bitrate);

	void finishSeekIfNecessary(int64_t videoTimeUs);
	void ensureCacheIsFetching_l();

	status_t startAudioPlayer_l(bool sendErrorNotification = true);

	void shutdownVideoDecoder_l();
	status_t setNativeWindow_l(const sp<ANativeWindow> &native);

	bool isStreamingHTTP() const;
	void sendCacheStats();

	enum FlagMode 
	{
		SET,
		CLEAR,
		ASSIGN
	};
	void modifyFlags(unsigned value, FlagMode mode);

	struct TrackStat 
	{
		String8 mMIME;
		String8 mDecoderName;
	};

	// protected by mStatsLock
	struct Stats
	{
		int mFd;
		String8 mURI;
		int64_t mBitrate;
		ssize_t mAudioTrackIndex;
		ssize_t mVideoTrackIndex;
		int64_t mNumVideoFramesDecoded;
		int64_t mNumVideoFramesDropped;
		int32_t mVideoWidth;
		int32_t mVideoHeight;
		uint32_t mFlags;
		Vector<TrackStat> mTracks;
	} mStats;

	AwesomePlayer(const AwesomePlayer &);
	AwesomePlayer &operator=(const AwesomePlayer &);
};

}  // namespace android

#endif  // AWESOME_PLAYER_H_

