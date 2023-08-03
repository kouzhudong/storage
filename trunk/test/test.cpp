// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "..\inc\Storage.h"
#include "encrypt.h"
#include "Disk.h"
#include "Folder.h"
#include "File.h"
#include "Volume.h"
#include "c.h"


#ifdef _WIN64  
#ifdef _DEBUG
#pragma comment(lib, "..\\x64\\Debug\\Storage.lib")
#else
#pragma comment(lib, "..\\x64\\Release\\Storage.lib")
#endif
#else 
#ifdef _DEBUG
#pragma comment(lib, "..\\Debug\\Storage.lib")
#else
#pragma comment(lib, "..\\Release\\Storage.lib")
#endif
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


int _cdecl main(_In_ int argc, _In_reads_(argc) CHAR * argv[])
{
    //__debugbreak();

    setlocale(LC_CTYPE, ".936");

    int Args;
    LPWSTR * Arglist = CommandLineToArgvW(GetCommandLineW(), &Args);
    if (NULL == Arglist) {
        //LOGA(ERROR_LEVEL, "LastError：%d", GetLastError());
        return GetLastError();
    }

    //DelDirTest(Args, Arglist);
    //GetDriveGeometryTest(argc, argv);

    //test_c();
    
    EnumSslProtocolProviders();

    LocalFree(Arglist);

    return STATUS_SUCCESS;
}
