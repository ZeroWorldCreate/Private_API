#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>

// 进程注入
#define PRC_INJECT_MODE_DLL 1
#define PRC_INJECT_MODE_SHELLCODE 2

#define DLL_INJECT_NOT_OPENPROCESS 1
#define DLL_INJECT_NOT_APPLY_MEMORY 2
#define DLL_INJECT_NOT_WRITE 3
#define DLL_INJECT_NOT_GET_MODULE 4
#define DLL_INJECT_NOT_FIND_HANDLE 5
#define DLL_INJECT_NOT_CREATE_THREAD 6
#define DLL_INJECT_NOT_RUN 7

struct Inject
{
	int LastError;	// 错误代码
	int ErrorWhy;	// 自定义错误码
};
// 进程注入

// 获取OS信息
#define GET_OS_NOT_CONNECT_DLL 1
#define GET_OS_NOT_FIND_HANDLE 2
#define GET_OS_NOT_GET_VERSION 3

#define WIN_2000 50
#define WIN_XP 51
#define WIN_SER_2003_OR_2003_R2 521
#define WIN_XP_X64 522
#define WIN_SER_2008 601
#define WIN_VISTA 602
#define WIN_SER_2008_R2 611
#define WIN_7 612
#define WIN_SER_2012 621
#define WIN_8 622
#define WIN_SER_2012_R2 631
#define WIN_8_1 632
#define WIN_SER_2016_OR_2019 101
#define WIN_10 102

struct OS
{
	int LastError;	// 错误代码
	int ErrorWhy;	// 自定义错误码

	bool IsCompatible;	// 是否处于兼容模式

	int T_OsVersion;	// 真实_系统版本号
	int T_BuildNumber;	// 真实_内部版本号
	char T_OsName[40];	// 真实_OS名

	int C_OsVersion;	// 兼容_系统版本号
	int C_BuildNumber;	// 兼容_内部版本号
	char C_OsName[40];	// 兼容_OS名
};
// 获取OS信息