#include "File.h"


void FileResourcesTest()
{
    LPCWSTR ResourceName = L"FileDescription";
    LPCWSTR FileName = L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\InputPersonalization.exe";
    GetFileResourcesW(FileName, ResourceName);
}


int WINAPI TestFileCallBack(_In_ TCHAR * FullFileName, _In_ PWIN32_FIND_DATA ffd, _In_opt_ PVOID Context)
{
    //fprintf(stderr, "FullFileName:%ls.\r\n", FullFileName);

    wstring tmp = L"\\DosDevices\\";
    tmp += FullFileName;
    GetFileHardLinkInformation(tmp.c_str());

    /*
    �ɿ���һ��map, key��__m128 FileId, ������list<wstring>.    
    */

    return 1;//������
}


int WINAPI ReparseFileCallBack(_In_ TCHAR * FullFileName, _In_ PWIN32_FIND_DATA ffd, _In_opt_ PVOID Context)
{
    if (FILE_ATTRIBUTE_REPARSE_POINT & ffd->dwFileAttributes) {
        fprintf(stderr, "FullFileName:%ls.\r\n", FullFileName);
        GetFileReparsePointInformation(FullFileName);
    }

    return 1;//������
}


void TestEnumFile()
{
    int ret = EnumFile(L"c:\\", ReparseFileCallBack, nullptr);
}
