#include "pch.h"
#include "PageFile.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL __stdcall EnumPageFileCallback(LPVOID pContext, PENUM_PAGE_FILE_INFORMATION pPageFileInfo, LPCSTR lpFilename)
/*
Parameters

pContext
The user-defined data passed from EnumPageFiles.

pPageFileInfo
A pointer to an ENUM_PAGE_FILE_INFORMATION structure.

lpFilename
The name of the pagefile.
注意：这个在MSDN的网页上显示的事错误的。
但头文件是对的。
主要看PENUM_PAGE_FILE_CALLBACKW还是PENUM_PAGE_FILE_CALLBACKA
即EnumPageFilesW还是EnumPageFilesA。
这个也可能是宽字符也可能是单字符。

Return value
To continue enumeration, the callback function must return TRUE.
To stop enumeration, the callback function must return FALSE.
*/
{
    printf("%ls.", (LPCWSTR)lpFilename);

    return TRUE;
}


int GetEnumPageFiles()
{
    setlocale(LC_CTYPE, ".936");

    //DebugBreak();

    BOOL B = EnumPageFilesW((PENUM_PAGE_FILE_CALLBACKW)EnumPageFileCallback, NULL);

    //回到运行完毕，放走这里。

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
