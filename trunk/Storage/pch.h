// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#pragma once


// 添加要在此处预编译的标头
#include "framework.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502
#endif

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define myheapalloc(x) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, x))
#define myheapfree(x)  (HeapFree(GetProcessHeap(), 0, x))


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef BOOL(WINAPI * LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

typedef DWORD(*PeCallBack)(_In_ PBYTE Data, _In_ DWORD Size, _In_opt_ PVOID Context);//回调函数的原型。

typedef BOOL(WINAPI * SetSecurityDescriptorControlFnPtr)(IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                                         IN SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
                                                         IN SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet);

//////////////////////////////////////////////////////////////////////////////////////////////////


void MyHandleError(LPCTSTR psz, int nErrorNumber);
LPCTSTR ErrorMessage(DWORD error);
void DisplayError(LPCTSTR lpszFunction);
void PrintError(_In_ DWORD Status);
void PrintError(LPCTSTR errDesc);
VOID ErrorExit(LPCWSTR wszErrorMessage, DWORD dwErrorCode);
void DisplayErrorBox(LPCTSTR lpszFunction);
void MyHandleError(const char * s);
void MyHandleError(LPCTSTR psz);
void LogApiErrMsg(PCSTR Api);

BOOL WINAPI SetCurrentProcessPrivilege(PCTSTR szPrivilege, BOOL fEnable);
BOOL IsWow64();
DWORD MapFile(_In_ LPCWSTR FileName, _In_opt_ PeCallBack CallBack, _In_opt_ PVOID Context);

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
);

void ByteToStr(DWORD cb, void * pv, LPSTR sz);

PCHAR WideCharToUTF8(IN LPWSTR pws);
LPWSTR UTF8ToWideChar(IN PCHAR utf8);


//////////////////////////////////////////////////////////////////////////////////////////////////
