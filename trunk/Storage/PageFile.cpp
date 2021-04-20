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
ע�⣺�����MSDN����ҳ����ʾ���´���ġ�
��ͷ�ļ��ǶԵġ�
��Ҫ��PENUM_PAGE_FILE_CALLBACKW����PENUM_PAGE_FILE_CALLBACKA
��EnumPageFilesW����EnumPageFilesA��
���Ҳ�����ǿ��ַ�Ҳ�����ǵ��ַ���

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

    //�ص�������ϣ��������

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
