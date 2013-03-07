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
#define LOG_TAG "OMXMaster"
#include <utils/Log.h>

#include "OMXMaster.h"

#include "SoftOMXPlugin.h"

#include <dlfcn.h>

#include <media/stagefright/MediaDebug.h>

namespace android {

OMXMaster::OMXMaster() : mVendorLibHandle(NULL) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	addVendorPlugin();
	addPlugin(new SoftOMXPlugin);
}

OMXMaster::~OMXMaster() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	clearPlugins();

	if (mVendorLibHandle != NULL) 
	{
		dlclose(mVendorLibHandle);
		mVendorLibHandle = NULL;
	}
}

void OMXMaster::addVendorPlugin() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、
*/
	addPlugin("libstagefrighthw.so");
}

void OMXMaster::addPlugin(const char *libname) 
{
/*
	参数:
		1、libname	: 传入一个动态库的名字
		
	返回:
		1、
		
	说明:
		1、执行过程:
			a) 打开传入的动态库
			b) 在打开的动态库找找到名为"createOMXPlugin"  的函数，如果这找不到那就
			    尝试名为"_ZN7android15createOMXPluginEv"  的函数是否能找到，如果都没找到
			    就返回
			c) 如果b  步骤找到了，则调用addPlugin(OMXPluginBase *plugin)  方法将b  步骤找到的
			    函数的返回值添加进入

			注意:  b  步骤中找到的函数返回值一定是个OMXPluginBase*  类型的
*/
	mVendorLibHandle = dlopen(libname, RTLD_NOW);

	if (mVendorLibHandle == NULL) 
	{
		return;
	}

	typedef OMXPluginBase *(*CreateOMXPluginFunc)();
	
	CreateOMXPluginFunc createOMXPlugin =  (CreateOMXPluginFunc)dlsym(mVendorLibHandle, "createOMXPlugin");
	
	if (!createOMXPlugin)
		createOMXPlugin = (CreateOMXPluginFunc)dlsym(mVendorLibHandle, "_ZN7android15createOMXPluginEv");

	if (createOMXPlugin) 
	{
		addPlugin( (*createOMXPlugin)() );
	}
}

void OMXMaster::addPlugin(OMXPluginBase *plugin) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参见上面addPlugin(const char *libname)  方法的说明
		2、注意: 
			一个OMXPluginBase*  即参数plugin  代表一个动态库，一个动态库内可能会有多个组件，所以
			一个plugin  与多个组件名字对应
*/
	Mutex::Autolock autoLock(mLock);

	mPlugins.push_back(plugin);

	OMX_U32 index = 0;

	char name[128];
	OMX_ERRORTYPE err;
	while ((err = plugin->enumerateComponents(name, sizeof(name), index++)) == OMX_ErrorNone) /* 遍历取出库中各个组件的名字*/
	{
		String8 name8(name);

		if (mPluginByComponentName.indexOfKey(name8) >= 0) /* 判断这个名字的组件是否存在，即是否已经在mPluginByComponentName  所表示的容器中*/
		{
			/* 存在*/
			ALOGE("A component of name '%s' already exists, ignoring this one.",name8.string());

			continue;
		}

		mPluginByComponentName.add(name8, plugin);/*  将一个组件名字与plugin  对应后插入到容器中。由此可见一个动态库的
													多个组件根据名字的不同都是与同一个plugin  对应后插入到容器中的*/
	}

	if (err != OMX_ErrorNoMore) 
	{
		ALOGE("OMX plugin failed w/ error 0x%08x after registering %d " "components", err, mPluginByComponentName.size());
	}
}

void OMXMaster::clearPlugins() 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参看addPlugin  方法
*/
	Mutex::Autolock autoLock(mLock);

	typedef void (*DestroyOMXPluginFunc)(OMXPluginBase*);
	DestroyOMXPluginFunc destroyOMXPlugin = (DestroyOMXPluginFunc)dlsym(mVendorLibHandle, "destroyOMXPlugin");

	mPluginByComponentName.clear();

	for (List<OMXPluginBase *>::iterator it = mPlugins.begin(); it != mPlugins.end(); ++it)
	{
		if (destroyOMXPlugin)
			destroyOMXPlugin(*it);
		else
			delete *it;
		
		*it = NULL;
	}

	mPlugins.clear();
}

OMX_ERRORTYPE OMXMaster::makeComponentInstance(const char *name,
													const OMX_CALLBACKTYPE *callbacks,
													OMX_PTR appData,
													OMX_COMPONENTTYPE **component)
{
/*
	参数:
		1、name		: 传入一个组件的名字
		2、callbacks		: 传入一个callback  的数据结构，供组件向往通知使用( OMX_CALLBACKTYPE 类型，由omx  标准制定的)
		3、appData		: 传入一个应用私有数据的指针，通常此值就是一个OMXNodeInstance  的实例
		4、component	: 用于返回代表一个组件数据结构的指针( OMX_COMPONENTTYPE 类型，由omx  标准制定的)
		
	返回:
		1、
		
	说明:
		1、注意:
			一个plugin  是一个OMXPluginBase  类型的数据结构，见方法addPlugin(const char *libname)  中的说明，一个plugin  是与
			一个动态库相互对应的，一个动态库中可能含有多个组件，其中各个组件的实例、销毁等操作
			都是通过plugin  来实现的
*/
	Mutex::Autolock autoLock(mLock);

	*component = NULL;

	ssize_t index = mPluginByComponentName.indexOfKey(String8(name));/* 利用传入的组件名字的前8 个字节，找到plugin 所对应的序号*/

	if (index < 0)
	{
		return OMX_ErrorInvalidComponentName;
	}

	OMXPluginBase *plugin = mPluginByComponentName.valueAt(index); /* 利用序号找到plugin 的实体*/
	OMX_ERRORTYPE err =  plugin->makeComponentInstance(name, callbacks, appData, component); /* 利用plugin  实例一个组件*/

	if (err != OMX_ErrorNone) 
	{
		return err;
	}

	mPluginByInstance.add(*component, plugin); /* 将组件指针域plugin  指针相对应后插入到容器中*/

	return err;
}

OMX_ERRORTYPE OMXMaster::destroyComponentInstance( OMX_COMPONENTTYPE *component) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、参见makeComponentInstance  方法，
*/
	Mutex::Autolock autoLock(mLock);

	ssize_t index = mPluginByInstance.indexOfKey(component);/* 根据组件指针找到plugin 所对应的序号*/

	if (index < 0) 
	{
		return OMX_ErrorBadParameter;
	}

	OMXPluginBase *plugin = mPluginByInstance.valueAt(index);/* 利用序号找到plugin 的实体*/
	mPluginByInstance.removeItemsAt(index);/* 将此序号所对应的单元从容器队列中清除*/

	return plugin->destroyComponentInstance(component); /* 调用plugin  的销毁组件函数对组件进行销毁*/
}

OMX_ERRORTYPE OMXMaster::enumerateComponents(OMX_STRING name,size_t size, OMX_U32 index) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、枚举组件的名字，参见addPlugin  说明，理解两个容器mPluginByComponentName、mPluginByInstance 
*/
	Mutex::Autolock autoLock(mLock);

	size_t numComponents = mPluginByComponentName.size();

	if (index >= numComponents) 
	{
		return OMX_ErrorNoMore;
	}

	const String8 &name8 = mPluginByComponentName.keyAt(index);

	CHECK(size >= 1 + name8.size());
	strcpy(name, name8.string());

	return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXMaster::getRolesOfComponent(const char *name,Vector<String8> *roles) 
{
/*
	参数:
		1、
		
	返回:
		1、
		
	说明:
		1、获取各个组件的规则，参见addPlugin  说明，理解两个容器mPluginByComponentName、mPluginByInstance 
*/
	Mutex::Autolock autoLock(mLock);

	roles->clear();

	ssize_t index = mPluginByComponentName.indexOfKey(String8(name));

	if (index < 0) 
	{
		return OMX_ErrorInvalidComponentName;
	}

	OMXPluginBase *plugin = mPluginByComponentName.valueAt(index);
	return plugin->getRolesOfComponent(name, roles);
}

}  // namespace android
