#include "Folder.h"


int DelDirTest(int argc, TCHAR * argv[])
/*
ɾ���ļ��������ְ취��
1.�ݹ������RemoveDirectory���Ƴ���Ŀ¼����ֻ��������Ҫȥ����
2.SHFileOperation������FO_DELETE��
�޸��ԣ�http://msdn.microsoft.com/en-us/library/windows/desktop/aa365200(v=vs.85).aspx�ȡ�

If you are writing a 32-bit application to list all the files in a directory and the application may be run on a 64-bit computer,
you should call the Wow64DisableWow64FsRedirectionfunction before calling FindFirstFile and call Wow64RevertWow64FsRedirection after the last call to FindNextFile.
*/
{
    setlocale(LC_CTYPE, ".936");

    TCHAR path[MAX_PATH] = L"e:\\test";

    bool b = DelDirByApi(path);

    DelDirByShell((TCHAR *)L"e:\\test2");

    return 0;
}
