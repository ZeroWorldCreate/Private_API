// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <fstream>
#include <string>
#include <Windows.h>

#pragma warning(disable: 4996)

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// 提升权限（管理员->调试级）
extern "C" _declspec(dllexport) bool EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        __try {
            if (hToken) {
                CloseHandle(hToken);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {};
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        __try {
            if (hToken) {
                CloseHandle(hToken);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {};
        return false;
    }

    return true;
}

// 进程注入
extern "C"  _declspec(dllexport) int ProcessInject(char DllPath[], char ShellCode[], int Target_PID, int Mode, Inject &Inject)
{
    BOOL bRet = false;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BYTE* pbProcessAddr = nullptr;
    int LastError = 0;
    int ErrorWhy = 0;
    DWORD dwPID = Target_PID;   // 赋值PID

    if (Mode == PRC_INJECT_MODE_DLL)
    {
        // 转义DLL路径
        char szDllPath[MAX_PATH] = { 0 };
        strcpy_s(szDllPath, DllPath);
        size_t nPathLen = (strlen(szDllPath) + 1); // 长度+1，结尾符

        do
        {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);    // 打开进程
            if (hProcess == INVALID_HANDLE_VALUE)  // 打开进程失败
            {
                ErrorWhy = DLL_INJECT_NOT_OPENPROCESS;
                LastError = GetLastError();
                break;
            }
            pbProcessAddr = (BYTE*)VirtualAllocEx(hProcess, nullptr, nPathLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!pbProcessAddr) // 申请内存空间失败
            {
                ErrorWhy = DLL_INJECT_NOT_APPLY_MEMORY;
                LastError = GetLastError();
                break;
            }
            if (0 == WriteProcessMemory(hProcess, pbProcessAddr, szDllPath, nPathLen, nullptr))
            {                   // 写入数据失败
                ErrorWhy = DLL_INJECT_NOT_WRITE;
                LastError = GetLastError();
                break;
            }
            HMODULE hModule = GetModuleHandleW(L"Kernel32");
            if (hModule == 0)   // 获取“Kernel32.dll”模块失败
            {
                ErrorWhy = DLL_INJECT_NOT_GET_MODULE;
                LastError = GetLastError();
                break;
            }
            PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
            if (pfnStartAddr == 0)  // 查找函数入口失败
            {
                ErrorWhy = DLL_INJECT_NOT_FIND_HANDLE;
                LastError = GetLastError();
                break;
            }
            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pfnStartAddr, pbProcessAddr, 0, nullptr);
            if (hThread == 0)   // 创建线程失败
            {
                ErrorWhy = DLL_INJECT_NOT_CREATE_THREAD;
                LastError = GetLastError();
                break;
            }
            if (!hThread)       // 注入代码无法被运行
            {
                ErrorWhy = DLL_INJECT_NOT_RUN;
                LastError = GetLastError();
                break;
            }
            bRet = true;
            // WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        } while (false);
    }
    else if (Mode == PRC_INJECT_MODE_SHELLCODE)
    {
        /*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,dwPID);
        pbProcessAddr = (BYTE *)VirtualAllocEx(hProcess, NULL, sizeof(ShellCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, pbProcessAddr, ShellCode, sizeof(ShellCode), NULL);
        CreateRemoteThread(hProcess,0,0,(LPTHREAD_START_ROUTINE)pbProcessAddr,NULL,0,NULL);*/
    }
    else
    {
        return 1;
    }
    if (bRet != TRUE)
    {
        Inject.LastError = LastError;
        Inject.ErrorWhy = ErrorWhy;
        return 1;
    }
    else
    {
        return 0;
    }
}

// 字节流加密（加解密一体，加密->未加密，未加密->加密，自动识别）
extern "C" _declspec(dllexport) int FileStreamEx(char FromFilePath[], int DataShift, char ToFilePath[])
{
    int LastError = 0;
    int ErrorWhy = 0;
    bool bRet = false;
    do
    {
        //打开源文件
        std::ifstream srcFile;//文件流对象
        srcFile.open(FromFilePath, std::ios::in | std::ios::binary);
        if (!srcFile)   // 打开文件失败
        {
            ErrorWhy = 1;
            LastError = GetLastError();
            break;
        }

        //获取源数据大小
        srcFile.seekg(0, std::ios::end);//设置文件偏移量到文件末尾
        std::streamoff size = srcFile.tellg();//得到文件偏移量距离文件头的字节数

        // 目标文件路径
        char buff[256] = { 0 };
        strcpy_s(buff, ToFilePath);

        // 创建目标文件
        std::ofstream dstFile;
        dstFile.open(buff, std::ios::out | std::ios::binary);
        if (!dstFile)   // 创建目标文件失败
        {
            ErrorWhy = 2;
            LastError = GetLastError();
            break;
        }
        srcFile.seekg(0, std::ios::beg);

        // 读取源文件内容并写入目的文件
        try
        {
            for (std::streamoff i = 0; i < size; i++) {
                dstFile.put(srcFile.get() ^ DataShift);//加密&解密
            }
        }
        catch (const std::exception&)   // 写入文件失败
        {
            ErrorWhy = 3;
            LastError = GetLastError();
            break;
        }

        // 释放内存
        dstFile.close();
        srcFile.close();

        bRet = true;
    } while (false);
    if (bRet != TRUE)
    {
        return LastError * 10 + ErrorWhy;     // 整数拼接：5*10 + 1 = 51 （拒绝访问--->打开文件失败）
    }
    else
    {
        return 0;
    }
}

// 获取OS信息
extern "C" _declspec(dllexport) bool GetOSInfo(OS &os)
{

    bool IsServer = NULL;   // 是否为服务器系统
    OSVERSIONINFOEXW S_osvi = { sizeof(S_osvi), 0, 0, 0, 0, {0}, 0, 0, 0, VER_NT_WORKSTATION };
    DWORDLONG const dwlConditionMask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
    IsServer = !VerifyVersionInfoW(&S_osvi, VER_PRODUCT_TYPE, dwlConditionMask);    // 服务端返回真

    typedef LONG(__stdcall* fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
    fnRtlGetVersion pRtlGetVersion;
    HMODULE hNtdll;
    LONG ntStatus;
    ULONG T_dwMajorVersion = 0;
    ULONG T_dwMinorVersion = 0;
    ULONG T_dwBuildNumber = 0;
    ULONG C_dwMajorVersion = 0;
    ULONG C_dwMinorVersion = 0;
    ULONG C_dwBuildNumber = 0;
    RTL_OSVERSIONINFOW VersionInformation = { 0 };

    typedef void (__stdcall* fnRtlGetNtVersionNumber)(DWORD*, DWORD*, DWORD*);
    fnRtlGetNtVersionNumber pRtlGetNtVersionNumber;

    bool bRet = true;   // 错误时取反
    int LastError = 0;
    int ErrorWhy = 0;

    int T_OsVersion = 0;
    int C_OsVersion = 0;
    do
    {
        hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)    // 无法链接动态链接库
        {
            bRet = false;
            ErrorWhy = 1;
            LastError = GetLastError();
            break;
        }

        pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        if (!pRtlGetVersion)    // 无法找到函数（RtlGetVersion）入口点
        {
            bRet = false;
            ErrorWhy = 2;
            LastError = GetLastError();
            break;
        }

        pRtlGetNtVersionNumber = (fnRtlGetNtVersionNumber)GetProcAddress(hNtdll, "RtlGetNtVersionNumbers");
        if (!pRtlGetNtVersionNumber)    // 无法找到函数（RtlGetNtVersionNumvers）入口点
        {
            bRet = false;
            ErrorWhy = 2;
            LastError = GetLastError();
            break;
        }

        VersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
        ntStatus = pRtlGetVersion(&VersionInformation); // RtlGetVersion
        if (ntStatus != 0)  // 获取版本号失败
        {
            bRet = false;
            ErrorWhy = 3;
            LastError = GetLastError();
            break;
        }

        pRtlGetNtVersionNumber(&T_dwMajorVersion, &T_dwMinorVersion, &T_dwBuildNumber); // RtlGetVersionNumbers
        T_dwBuildNumber &= 0xffff;
        if (T_dwMajorVersion == 0)    // 获取版本号失败
        {
            bRet = false;
            ErrorWhy = 3;
            LastError = GetLastError();
            break;
        }

        C_dwMajorVersion = VersionInformation.dwMajorVersion;
        C_dwMinorVersion = VersionInformation.dwMinorVersion;
        C_dwBuildNumber = VersionInformation.dwBuildNumber;

        // 是否处于兼容模式
        if (T_dwMajorVersion != VersionInformation.dwMajorVersion)
        {
            os.IsCompatible = true;
        }
        if (T_dwMinorVersion != VersionInformation.dwMinorVersion)
        {
            os.IsCompatible = true;
        }
        if (T_dwBuildNumber != VersionInformation.dwBuildNumber)
        {
            os.IsCompatible = true;
        }

        switch (T_dwMajorVersion)
        {
        case 5:
            switch (T_dwMinorVersion)
            {
            case 0: // Windows 2000
                T_OsVersion = WIN_2000;
                strcpy_s(os.T_OsName, "Windows 2000");
                break;
            case 1: // Windows XP
                T_OsVersion = WIN_XP;
                strcpy_s(os.T_OsName, "Windows XP");
                break;
            case 2: // Windows XP x64 / Server 2003 / Server 2003 R2
                if (IsServer)
                {
                    // Windows Server 2003 / Server 2003 R2
                    T_OsVersion = WIN_SER_2003_OR_2003_R2;
                    strcpy_s(os.T_OsName, "Windows Server 2003 / Server 2003 R2");
                    break;
                }
                else
                {
                    // Windows XP x64
                    T_OsVersion = WIN_XP_X64;
                    strcpy_s(os.T_OsName, "Windows XP x64");
                    break;
                }
            default:
                break;
            }
            break;
        case 6:
            switch (T_dwMinorVersion)
            {
            case 0: // Windows Vista / Server 2008
                if (IsServer)
                {
                    // Windows Server 2008
                    T_OsVersion = WIN_SER_2008;
                    strcpy_s(os.T_OsName, "Windows Server 2008");
                    break;
                }
                else
                {
                    // Windows Vista
                    T_OsVersion = WIN_VISTA;
                    strcpy_s(os.T_OsName, "Windows Vista");
                    break;
                }
            case 1: // WIndows 7 / Windows Server 2008 R2
                if (IsServer)
                {
                    // Windows Server 2008 R2
                    T_OsVersion = WIN_SER_2008_R2;
                    strcpy_s(os.T_OsName, "Windows Server 2008 R2");
                    break;
                }
                else
                {
                    // Windows 7
                    T_OsVersion = WIN_7;
                    strcpy_s(os.T_OsName, "Windows 7");
                    break;
                }
            case 2: // Windows 8 / Server 2012
                if (IsServer)
                {
                    // Windows Server 2012
                    T_OsVersion = WIN_SER_2012;
                    strcpy_s(os.T_OsName, "Windows Server 2012");
                    break;
                }
                else
                {
                    // Windows 8
                    T_OsVersion = WIN_8;
                    strcpy_s(os.T_OsName, "Windows 8");
                    break;
                }
            case 3: // Windows 8.1 / Server 2012 R2
                if (IsServer)
                {
                    // Windows Server 2012 R2
                    T_OsVersion = WIN_SER_2012_R2;
                    strcpy_s(os.T_OsName, "Windows Server 2012 R2");
                    break;
                }
                else
                {
                    // Windows 8.1
                    T_OsVersion = WIN_8_1;
                    strcpy_s(os.T_OsName, "Windows 8.1");
                    break;
                }
            default:
                break;
            }
            break;
        case 10:    // Windows 10 / Server 2016 / Server 2019
            if (IsServer)
            {
                // Windows Server 2016 / Server 2019
                T_OsVersion = WIN_SER_2016_OR_2019;
                strcpy_s(os.T_OsName, "Windows Server 2016 / Server 2019");
                break;
            }
            else
            {
                // Windows 10
                T_OsVersion = WIN_10;
                strcpy_s(os.T_OsName,"Windows 10");
                break;
            }
        default:
            break;
        }


        switch (C_dwMajorVersion)
        {
        case 5:
            switch (C_dwMinorVersion)
            {
            case 0: // Windows 2000
                C_OsVersion = WIN_2000;
                strcpy_s(os.C_OsName, "Windows 2000");
                break;
            case 1: // Windows XP
                C_OsVersion = WIN_XP;
                strcpy_s(os.C_OsName, "Windows XP");
                break;
            case 2: // Windows XP x64 / Server 2003 / Server 2003 R2
                if (IsServer)
                {
                    // Windows Server 2003 / Server 2003 R2
                    C_OsVersion = WIN_SER_2003_OR_2003_R2;
                    strcpy_s(os.C_OsName, "Windows Server 2003 / Server 2003 R2");
                    break;
                }
                else
                {
                    // Windows XP x64
                    C_OsVersion = WIN_XP_X64;
                    strcpy_s(os.C_OsName, "Windows XP x64");
                    break;
                }
            default:
                break;
            }
            break;
        case 6:
            switch (C_dwMinorVersion)
            {
            case 0: // Windows Vista / Server 2008
                if (IsServer)
                {
                    // Windows Server 2008
                    C_OsVersion = WIN_SER_2008;
                    strcpy_s(os.C_OsName, "Windows Server 2008");
                    break;
                }
                else
                {
                    // Windows Vista
                    C_OsVersion = WIN_VISTA;
                    strcpy_s(os.C_OsName, "Windows Vista");
                    break;
                }
            case 1: // WIndows 7 / Windows Server 2008 R2
                if (IsServer)
                {
                    // Windows Server 2008 R2
                    C_OsVersion = WIN_SER_2008_R2;
                    strcpy_s(os.C_OsName, "Windows Server 2008 R2");
                    break;
                }
                else
                {
                    // Windows 7
                    C_OsVersion = WIN_7;
                    strcpy_s(os.C_OsName, "Windows 7");
                    break;
                }
            case 2: // Windows 8 / Server 2012
                if (IsServer)
                {
                    // Windows Server 2012
                    C_OsVersion = WIN_SER_2012;
                    strcpy_s(os.C_OsName, "Windows Server 2012");
                    break;
                }
                else
                {
                    // Windows 8
                    C_OsVersion = WIN_8;
                    strcpy_s(os.C_OsName, "Windows 8");
                    break;
                }
            case 3: // Windows 8.1 / Server 2012 R2
                if (IsServer)
                {
                    // Windows Server 2012 R2
                    C_OsVersion = WIN_SER_2012_R2;
                    strcpy_s(os.C_OsName, "Windows Server 2012 R2");
                    break;
                }
                else
                {
                    // Windows 8.1
                    C_OsVersion = WIN_8_1;
                    strcpy_s(os.C_OsName, "Windows 8.1");
                    break;
                }
            default:
                break;
            }
            break;
        case 10:    // Windows 10 / Server 2016 / Server 2019
            if (IsServer)
            {
                // Windows Server 2016 / Server 2019
                C_OsVersion = WIN_SER_2016_OR_2019;
                strcpy_s(os.C_OsName, "Windows Server 2016 / Server 2019");
                break;
            }
            else
            {
                // Windows 10
                C_OsVersion = WIN_10;
                strcpy_s(os.C_OsName, "Windows 10");
                break;
            }
        default:
            break;
        }
        FreeLibrary(hNtdll);
        break;
    } while (false);
    if (!bRet)
    {
        os.LastError = LastError;
        os.ErrorWhy = ErrorWhy;
        return false;
    }
    os.T_OsVersion = T_OsVersion;
    os.T_BuildNumber = T_dwBuildNumber;
    os.C_OsVersion = C_OsVersion;
    os.C_BuildNumber = C_dwBuildNumber;
    return true;    // OsVersion为0时，为未知系统
}

// 获取CPU信息
#include <intrin.h>
extern "C" _declspec(dllexport) bool GetCPUInfo()
{
    int CpuInfo[4] = { -1 };
    char CpuFacture[32] = { 0 };
    char CpuType[32] = { 0 };
    char CpuFreq[32] = { 0 };

    __cpuid(CpuInfo, 0x80000002);
    memcpy(CpuFacture, CpuInfo, sizeof(CpuInfo));

    __cpuid(CpuInfo, 0x80000003);
    memcpy(CpuType, CpuInfo, sizeof(CpuInfo));

    __cpuid(CpuInfo, 0x80000004);
    memcpy(CpuFreq, CpuInfo, sizeof(CpuInfo));

    return true;
}