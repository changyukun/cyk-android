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

//
#ifndef ANDROID_IINTERFACE_H
#define ANDROID_IINTERFACE_H

#include <binder/Binder.h>

namespace android {

// ----------------------------------------------------------------------

class IInterface : public virtual RefBase
{
public:
            IInterface();
            sp<IBinder>         asBinder();
            sp<const IBinder>   asBinder() const;
            
protected:
    virtual                     ~IInterface();
    virtual IBinder*            onAsBinder() = 0;
};

// ----------------------------------------------------------------------

/*
	参看函数sp<IServiceManager> defaultServiceManager()  中的说明

	形如下的代码调用:
	aaa = interface_cast<IAudioFlinger>(binder);
	等价于:
	aaa = IAudioFlinger::asInterface(binder);
	即调用方法asInterface
*/
template<typename INTERFACE>
inline sp<INTERFACE> interface_cast(const sp<IBinder>& obj)
{
    return INTERFACE::asInterface(obj);
}

// ----------------------------------------------------------------------
/*
	BnXXX  模板类定义

	形如class BnMediaPlayerService : public BnInterface<IMediaPlayerService>  调用

	相当于定义一个类BnMediaPlayerService，此类继承了IMediaPlayerService 类和BBinder 类

		如下调用:
		class AAAA : public BnInterface<IXXXXX>
		等价于===>
		class AAAA : public IXXXXX, public BBinder  
		即AAAA 类继承了IXXXXX 和BBinder  两个类
*/
template<typename INTERFACE>
class BnInterface : public INTERFACE, public BBinder
{
public:
    virtual sp<IInterface>      queryLocalInterface(const String16& _descriptor);
    virtual const String16&     getInterfaceDescriptor() const;

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------
/*
	BpXXX  模板类定义

	参见BnInterface  模板类的说明
*/
template<typename INTERFACE>
class BpInterface : public INTERFACE, public BpRefBase
{
public:
                                BpInterface(const sp<IBinder>& remote);

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

/* 
	声明部分宏定义
*/
#define DECLARE_META_INTERFACE(INTERFACE)                               							\
	static const android::String16 descriptor;                          									\
	static android::sp<I##INTERFACE> asInterface(const android::sp<android::IBinder>& obj);         	\
	virtual const android::String16& getInterfaceDescriptor() const;    								\
	I##INTERFACE();                                                     										\
	virtual ~I##INTERFACE();                                            										\


/* 
	实现部分宏定义
	参看函数sp<IServiceManager> defaultServiceManager()  中的说明
	即说明中使用的方法IServiceManager::asInterface()  就是通过这个宏来实现的
*/
#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       									\
																									\
	const android::String16 I##INTERFACE::descriptor(NAME);             										\
																									\
	const android::String16&  I##INTERFACE::getInterfaceDescriptor() const 									\
	{              																						\
		return I##INTERFACE::descriptor;                                												\
	}                                                                   															\
																									\
	android::sp<I##INTERFACE> I##INTERFACE::asInterface(const android::sp<android::IBinder>& obj)                 	\
	{                                                                   															\
		android::sp<I##INTERFACE> intr;                                 											\
		if (obj != NULL) 																				\
		{                                              																	\
			intr = static_cast<I##INTERFACE*>(obj->queryLocalInterface(I##INTERFACE::descriptor).get());        	\
			if (intr == NULL) 																			\
			{                                         																\
				intr = new Bp##INTERFACE(obj);                          										\
			}                                                           														\
		}                                                               														\
		return intr;                                                    														\
	}                                                                   															\
																									\
	I##INTERFACE::I##INTERFACE() { }                                    											\
	I##INTERFACE::~I##INTERFACE() { }                                   											\


#define CHECK_INTERFACE(interface, data, reply)                         		\
    if (!data.checkInterface(this)) { return PERMISSION_DENIED; }       	\


// ----------------------------------------------------------------------
// No user-serviceable parts after this...

template<typename INTERFACE>
inline sp<IInterface> BnInterface<INTERFACE>::queryLocalInterface(
        const String16& _descriptor)
{
    if (_descriptor == INTERFACE::descriptor) return this;
    return NULL;
}

template<typename INTERFACE>
inline const String16& BnInterface<INTERFACE>::getInterfaceDescriptor() const
{
    return INTERFACE::getInterfaceDescriptor();
}

template<typename INTERFACE>
IBinder* BnInterface<INTERFACE>::onAsBinder()
{
    return this;
}

template<typename INTERFACE>
inline BpInterface<INTERFACE>::BpInterface(const sp<IBinder>& remote)
    : BpRefBase(remote)
{
}

template<typename INTERFACE>
inline IBinder* BpInterface<INTERFACE>::onAsBinder()
{
    return remote();
}
    
// ----------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_IINTERFACE_H
