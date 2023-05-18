#include "File.h"


void FileResourcesTest()
{
    LPCWSTR ResourceName = L"FileDescription";
    LPCWSTR FileName = L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\InputPersonalization.exe";
    GetFileResourcesW(FileName, ResourceName);
}


int WINAPI TestFileCallBack(_In_ TCHAR * FullFileName, _In_ PWIN32_FIND_DATA ffd, _In_opt_ PVOID Context)
{
    fprintf(stderr, "FullFileName:%ls.\r\n", FullFileName);

    return 1;
}


void TestEnumFile()
{
    int ret = EnumFile(L"d:\\", TestFileCallBack, nullptr);
}
