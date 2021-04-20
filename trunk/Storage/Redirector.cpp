#include "pch.h"
#include "Redirector.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef NTDDI_VERSION
#undef NTDDI_VERSION
#endif
#define NTDDI_VERSION 0x05010000


void DisFileRedirectionTest()
/*
Disables file system redirection for the calling thread. 
File system redirection is enabled by default.

The following example uses Wow64DisableWow64FsRedirection to disable file system redirection so that 
a 32-bit application that is running under WOW64 can open the 64-bit version of Notepad.exe in 
%SystemRoot%\System32 instead of being redirected to the 32-bit version in %SystemRoot%\SysWOW64.

https://docs.microsoft.com/zh-cn/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection?redirectedfrom=MSDN
*/
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PVOID OldValue = NULL;

    //  Disable redirection immediately prior to the native API
    //  function call.
    if (Wow64DisableWow64FsRedirection(&OldValue)) {
        //  Any function calls in this block of code should be as concise
        //  and as simple as possible to avoid unintended results.
        hFile = CreateFile(TEXT("C:\\Windows\\System32\\Notepad.exe"),
                           GENERIC_READ,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);

        //  Immediately re-enable redirection. Note that any resources
        //  associated with OldValue are cleaned up by this call.
        if (FALSE == Wow64RevertWow64FsRedirection(OldValue)) {
            //  Failure to re-enable redirection should be considered
            //  a criticial failure and execution aborted.
            return;
        }
    }

    //  The handle, if valid, now can be used as usual, and without
    //  leaving redirection disabled. 
    if (INVALID_HANDLE_VALUE != hFile) {
        // Use the file handle
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
