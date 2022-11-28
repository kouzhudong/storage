#include "File.h"


void FileResourcesTest()
{
    LPCWSTR ResourceName = L"FileDescription";
    LPCWSTR FileName = L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\InputPersonalization.exe";
    GetFileResourcesW(FileName, ResourceName);
}
