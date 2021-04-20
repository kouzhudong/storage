// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"

// 当使用预编译的头时，需要使用此源文件，编译才能成功。


#pragma warning(disable:6067)
#pragma warning(disable:28183)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


void MyHandleError(LPCTSTR psz, int nErrorNumber)
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}


void DisplayError(LPCTSTR lpszFunction)
// Routine Description:
// Retrieve and output the system error message for the last-error code
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
                           (lstrlen((LPCTSTR)lpMsgBuf)
                            + lstrlen((LPCTSTR)lpszFunction)
                            + 40) // account for format string
                           * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
                               LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                               TEXT("%s failed with error code %d as follows:\n%s"),
                               lpszFunction,
                               dw,
                               lpMsgBuf))) {
        printf("FATAL ERROR: Unable to output error code.\n");
    }

    _tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


LPCTSTR ErrorMessage(DWORD error)
//  ErrorMessage support function.
//  Retrieves the system error message for the GetLastError() code.
//  Note: caller must use LocalFree() on the returned LPCTSTR buffer.
{
    LPVOID lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                  | FORMAT_MESSAGE_FROM_SYSTEM
                  | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  error,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&lpMsgBuf,
                  0,
                  NULL);

    return((LPCTSTR)lpMsgBuf);
}


void PrintError(_In_ DWORD Status)
//  PrintError
//  Prints error information to the console
{
    wprintf(L"Error: 0x%08x (%d)\n", Status, Status);
}


void PrintError(LPCTSTR errDesc)
//  PrintError support function.
//  Simple wrapper function for error output.
{
    LPCTSTR errMsg = ErrorMessage(GetLastError());
    _tprintf(TEXT("\n** ERROR ** %s: %s\n"), errDesc, errMsg);
    LocalFree((LPVOID)errMsg);
}


VOID ErrorExit(LPCWSTR wszErrorMessage, DWORD dwErrorCode)
//------------------------------------------------------------------
//  A simple error handling function that prints an error message 
//  and exits the program. 
//
//  TODO: Replace this function with one that has better error 
//  reporting.
//
{
    fwprintf(stderr, L"An error occurred in running the program. \n");
    fwprintf(stderr, L"%s\n", wszErrorMessage);
    fwprintf(stderr, L"Error code: 0x%08x\n", dwErrorCode);
    fwprintf(stderr, L"Program terminating. \n");
    exit(1);
}


void DisplayErrorBox(LPCTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and clean up

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
                                      (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
                    LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                    TEXT("%s failed with error %d: %s"),
                    lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


void MyHandleError(const char * s)
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the 
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.
{
    printf("An error occurred in running the program.\n");
    printf("%s\n", s);
    printf("Error number %x\n.", GetLastError());
    printf("Program terminating.\n");
    exit(1);
}


void MyHandleError(LPCTSTR psz)
//-------------------------------------------------------------------
//    This example uses the function MyHandleError, a simple error
//    handling function, to print an error message to the standard  
//    error (stderr) file and exit the program. 
//    For most applications, replace this function with one 
//    that does more extensive error reporting.
{
    _ftprintf(stderr, TEXT("An error occurred in running the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
    _ftprintf(stderr, TEXT("Program terminating. \n"));
    exit(1);
} // End of MyHandleError


void LogApiErrMsg(PCSTR Api)
/*
功能：专门用于记录API调用失败的信息。

做法有二：
1.返回API失败原因的详细描述，感觉用法有点别扭。
2.支持不定参数。
3.
*/
{
    LPWSTR lpvMessageBuffer;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL,
                  GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPWSTR)&lpvMessageBuffer,//特别注意：数据后有回车换行，而且还有垃圾数据。
                  0,
                  NULL);

    //去掉回车换行
    int x = lstrlenW((LPWSTR)lpvMessageBuffer);
    lpvMessageBuffer[x - 1] = 0;
    lpvMessageBuffer[x - 2] = 0;

    //LOGA(ERROR_LEVEL, "API:%s, LastError:%#x, Message:%ls", Api, GetLastError(), lpvMessageBuffer);

    LocalFree(lpvMessageBuffer);
}


BOOL WINAPI SetCurrentProcessPrivilege(PCTSTR szPrivilege, BOOL fEnable)
/*
功能：本进程的特权开启的开关。

如：
EnablePrivilege(SE_DEBUG_NAME, TRUE);
EnablePrivilege(SE_DEBUG_NAME, FALSE);
*/
{
    // Enabling the debug privilege allows the application to see information about service applications
    BOOL fOk = FALSE;    // Assume function fails
    HANDLE hToken;

    // Try to open this process's access token
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        // Attempt to modify the given privilege
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, szPrivilege, &tp.Privileges[0].Luid);

        tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        fOk = (GetLastError() == ERROR_SUCCESS);

        CloseHandle(hToken);// Don't forget to close the token handle
    }

    return(fOk);
}


BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;

#ifdef _WIN64
    // 64-bit code, obviously not running in a 32-bit process
    return false;
#endif

#pragma warning(push)
#pragma warning(disable:4702)
    HMODULE ModuleHandle = GetModuleHandle(TEXT("kernel32"));
    if (NULL != ModuleHandle) {
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(ModuleHandle,
                                                                                   "IsWow64Process");
        if (NULL != fnIsWow64Process) {
            if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64)) {
                // handle error
            }
        }
    }

    return bIsWow64;
#pragma warning(pop)
}


DWORD MapFile(_In_ LPCWSTR FileName, _In_opt_ PeCallBack CallBack, _In_opt_ PVOID Context)
{
    DWORD LastError = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapFile = NULL;
    PBYTE FileContent = NULL;

    if (IsWow64()) {//在wow64下关闭文件重定向。
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(FALSE);
        _ASSERTE(bRet);
    }

    __try {
        hFile = CreateFile(FileName,
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            LastError = GetLastError();
            //LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFile");
            __leave;
        }

        LARGE_INTEGER FileSize = {0};
        if (0 == GetFileSizeEx(hFile, &FileSize)) {
            LastError = GetLastError();
            //LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("GetFileSizeEx");
            __leave;
        }

        if (0 == FileSize.QuadPart) {//如果文件大小为0.
            LastError = ERROR_EMPTY;
            //LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        if (FileSize.HighPart) {//暂时不支持大文件。
            LastError = ERROR_EMPTY;
            //LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* 空文件则返回失败 */
        if (hMapFile == NULL) {
            LastError = GetLastError();
            //LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        FileContent = (PBYTE)MapViewOfFile(hMapFile, SECTION_MAP_READ, NULL, NULL, 0/*映射所有*/);
        if (FileContent == NULL) {
            LastError = GetLastError();
            //LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        if (CallBack) {
            __try {
                LastError = CallBack(FileContent, FileSize.LowPart, Context);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                LastError = GetExceptionCode();
                //LOGA(ERROR_LEVEL, "ExceptionCode:%#x", LastError);
            }
        }
    } __finally {
        if (FileContent) {
            UnmapViewOfFile(FileContent);
        }

        if (hMapFile) {
            CloseHandle(hMapFile);
        }

        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }
    }

    if (IsWow64()) {
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(TRUE);//Enable WOW64 file system redirection. 
        _ASSERTE(bRet);
    }

    return LastError;
}


BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
/*
The following example shows how to enable or disable a privilege in an access token. 
The example calls the LookupPrivilegeValue function to get the locally unique identifier (LUID) that the local system uses to identify the privilege.
Then the example calls the AdjustTokenPrivileges function, which either enables or disables the privilege that depends on the value of the bEnablePrivilege parameter.

https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
*/
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}


void ByteToStr(DWORD cb, void * pv, LPSTR sz)
// This program uses the function ByteToStr to convert an array of BYTEs to a char string. 
// Parameters passed are:
//    pv is the array of BYTEs to be converted.
//    cb is the number of BYTEs in the array.
//    sz is a pointer to the string to be returned.
{
    //  Declare and initialize local variables.
    BYTE * pb = (BYTE *)pv; // local pointer to a BYTE in the BYTE array
    DWORD i;               // local loop counter
    int b;                 // local variable

    //  Begin processing loop.
    for (i = 0; i < cb; i++) {
        b = (*pb & 0xF0) >> 4;
        *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
        b = *pb & 0x0F;
        *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
        pb++;
    }

    *sz++ = 0;
}


PCHAR WideCharToUTF8(IN LPWSTR pws)
/*
得到的内存有调用者释放。
*/
{
    int cchWideChar = WideCharToMultiByte(CP_UTF8, 0, pws, lstrlenW(pws), NULL, 0, NULL, NULL);

    size_t utf8_len = ((size_t)cchWideChar + 1) * sizeof(WCHAR) * 2;
    char * utf8 = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, utf8_len);
    _ASSERTE(NULL != utf8);

    size_t ret = WideCharToMultiByte(CP_UTF8, 0, pws, lstrlenW(pws), utf8, (int)utf8_len, NULL, NULL);
    _ASSERTE(ret);

    return utf8;
}


LPWSTR UTF8ToWideChar(IN PCHAR utf8)
/*
得到的内存有调用者释放。
*/
{
    int cchWideChar = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, 0, 0);

    LPWSTR pws = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)cchWideChar * 4);
    if (pws) {
        int ret = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, pws, cchWideChar);//utf8->Unicode
        _ASSERTE(ret);
    } else {
        //LOGA(ERROR_LEVEL, "申请内存失败");
    }

    return pws;
}
