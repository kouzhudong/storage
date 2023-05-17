// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"


void GetSomeApiAddress()
{
    HMODULE ModuleHandle = GetModuleHandle(TEXT("ntdll.dll"));
    if (NULL != ModuleHandle) {
        g_NtOpenFile = (NtOpenFile_Fn)GetProcAddress(ModuleHandle, "NtOpenFile");
        if (NULL == g_NtOpenFile) {
            printf("没有找到NtOpenFile函数\n");
        }

        NtQueryInformationFile = (NtQueryInformationFile_Fn)
            GetProcAddress(ModuleHandle, "NtQueryInformationFile");
        if (NULL == NtQueryInformationFile) {
            printf("没有找到NtQueryInformationFile函数\n");
        }

        g_NtClose = (NtClose_Fn)GetProcAddress(ModuleHandle, "NtClose");
        if (NULL == g_NtClose) {
            printf("没有找到NtClose函数\n");
        }
    }
}


void init()
{
    setlocale(LC_CTYPE, ".936");
    GetSomeApiAddress();
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:        
        init();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
