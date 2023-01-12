/*
本文包括目录的：
1.遍历。
2.监控。
3.其他。
*/


/*
监控目录的变化的办法有：
1.SHChangeNotifyRegister（SHChangeNotify）。
2.FindFirstChangeNotification和FindNextChangeNotification没有变化的类型。
3.ReadDirectoryChangesW有时会遗漏信息，可以结合使用完成例程,i/o端口（CreateIoCompletionPort）等异步多线程措施。
4.Change Journal（USN Journal）只能在NTFS，REFS上。
5.文件系统过滤驱动.
6.hook api and messages.
7.其他（如备份一份，周期的比较）.
8.ICopyHook接口的回调函数.
9.其他。
*/


#pragma once


class Directory
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


#define BUFSIZE MAX_PATH


#define MAX_BUFFER  4096


typedef struct _PER_IO_CONTEXT {//自定义结构，即“完成键”(单句柄数据)
    OVERLAPPED  ol;
    HANDLE      hIocp;
    HANDLE      hDir;
    TCHAR       lpszDirName[MAX_PATH];
    CHAR        lpBuffer[MAX_BUFFER];
}PER_IO_CONTEXT, * PPER_IO_CONTEXT;


#define MAX_DIRS    99


typedef struct _DIRECTORY_INFO {
    OVERLAPPED  Overlapped;
    HANDLE      hDir;
    TCHAR       lpszDirName[MAX_PATH];

    CHAR        lpBuffer[MAX_BUFFER];
    DWORD       dwBufLength;
}DIRECTORY_INFO, * PDIRECTORY_INFO, * LPDIRECTORY_INFO;


#define MY_BUFSIZE 1024 // Buffer size for console window titles.


// Fixed co-ordinates and size.
#define SCREEN_RELATIVE_WIDTH_DIFFERNCE 310
#define SCREEN_RELATIVE_HEIGHT_DIFFERENCE 148
#define WINDOW_WIDTH 300
#define WINDOW_HEIGHT 120


//////////////////////////////////////////////////////////////////////////////////////////////////
