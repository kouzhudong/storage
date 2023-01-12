#include "pch.h"
#include "Version.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI GetFileVersion(PWCHAR FileName, VS_FIXEDFILEINFO * FileInfo)
/*
功能：获取文件的版本信息。

参考：\Windows-classic-samples\Samples\Win7Samples\sysmgmt\msi\setup.exe\utils.cpp的GetFileVersionNumber函数。
*/
{
    DWORD lpdwHandle = 0;
    DWORD D = GetFileVersionInfoSize(FileName, &lpdwHandle);
    if (!D) {
        //LOGW(ERROR_LEVEL, "FileName:%ls, GetLastError:%#x", FileName, GetLastError());
        return;
    }

    LPVOID lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, D);
    if (NULL == lpData) {
        //LOGA(ERROR_LEVEL, "申请内存失败");
        return;
    }

    BOOL B = GetFileVersionInfo(FileName, 0, D, lpData);
    if (!B) {
        //LOGW(ERROR_LEVEL, "FileName:%ls, GetLastError:%#x", FileName, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    VS_FIXEDFILEINFO * lpVSFixedFileInfo = NULL;
    unsigned          uiSize;
    B = VerQueryValue(lpData, L"\\", (LPVOID *)&lpVSFixedFileInfo, &uiSize) && (uiSize != 0);
    if (!B) {
        //LOGW(ERROR_LEVEL, "FileName:%ls, GetLastError:%#x", FileName, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    *FileInfo = *lpVSFixedFileInfo;

    HeapFree(GetProcessHeap(), 0, lpData);
}


EXTERN_C
__declspec(dllexport)
void WINAPI GetFileResourcesW(IN LPCWSTR FileName, IN LPCWSTR ResourceName)
/*
功能：获取文件资源的一些信息。

参数：
FileName 文件名。注意：有时会传递过来：\SystemRoot\System32\smss.exe。
ResourceName 资源名，此项不可乱写，支持的选项有：
    Comments
    InternalName
    ProductName
    CompanyName
    LegalCopyright
    ProductVersion
    FileDescription
    LegalTrademarks
    PrivateBuild
    FileVersion
    OriginalFilename
    SpecialBuild。
result 想要的结果，注意字符的编码，有的是汉字，有的是特殊字符。

参考：
1.\Windows-classic-samples\Samples\Win7Samples\sysmgmt\msi\setup.exe\utils.cpp的GetFileVersionNumber函数。
2.https://docs.microsoft.com/en-us/windows/win32/api/winver/nf-winver-verqueryvaluea
3.https://blog.csdn.net/Simon798/article/details/102836496

因为：有特殊字符，且ansi不能表示特殊字符，所以不能有A版的，只有W版本的。
*/
{
    DWORD lpdwHandle = 0;
    DWORD D = GetFileVersionInfoSize(FileName, &lpdwHandle);
    if (!D) {//0x715 == 找不到映像文件中指定的资源类型。
        DWORD LastError = GetLastError();
        if (ERROR_RESOURCE_TYPE_NOT_FOUND != LastError && ERROR_FILE_NOT_FOUND != LastError) {
            //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, LastError);
        }
        return;
    }

    LPVOID lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, D);
    if (NULL == lpData) {
        //LOGA(ERROR_LEVEL, "申请内存失败");
        return;
    }

    BOOL B = GetFileVersionInfo(FileName, 0, D, lpData);
    if (!B) {
        //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    // Read the list of languages and code pages.
    unsigned cbTranslate;
    B = VerQueryValue(lpData, L"\\VarFileInfo\\Translation", (LPVOID *)&lpTranslate, &cbTranslate);
    if (!B) {
        DWORD LastError = GetLastError();
        if (ERROR_RESOURCE_TYPE_NOT_FOUND == LastError || ERROR_FILE_NOT_FOUND == LastError) {
            //DbgPrintA("警告：FileName:%ls, LastError:%#x", FileName, LastError);
        } else {
            //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, LastError);
        }
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    // Read the file description for each language and code page.
    int count = (cbTranslate / sizeof(struct LANGANDCODEPAGE));

    if (0 == count) {
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    if (count > 1) {
        //DbgPrintA("重要信息：FileName:%ls, 文件属性里的代码页/语言的配置支持多个, count:%#x", FileName, count);
    }

    for (int i = 0; i < count; i++) {
        WCHAR SubBlock[MAX_PATH] = {0};
        HRESULT hr = StringCchPrintf(SubBlock,
                                     MAX_PATH,
                                     L"\\StringFileInfo\\%04x%04x\\%s",
                                     lpTranslate[i].wLanguage,
                                     lpTranslate[i].wCodePage,
                                     ResourceName);
        if (FAILED(hr)) {
            //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, GetLastError());
            break;
        }

        // Retrieve file description for language and code page "i". 
        VS_FIXEDFILEINFO * lpBuffer = NULL;
        unsigned          dwBytes;
        B = VerQueryValue(lpData, SubBlock, (LPVOID *)&lpBuffer, &dwBytes);
        if (!B) {//YourPhoneServer.exe 和 YourPhone.exe明明有资源却返回0x715。
            DWORD LastError = GetLastError();
            if (ERROR_RESOURCE_TYPE_NOT_FOUND != LastError) {
                //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, LastError);
            }
            break;
        }

        printf("%ls", (PWCHAR)lpBuffer);
    }

    HeapFree(GetProcessHeap(), 0, lpData);
}
