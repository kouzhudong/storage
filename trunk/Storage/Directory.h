/*
���İ���Ŀ¼�ģ�
1.������
2.��ء�
3.������
*/


/*
���Ŀ¼�ı仯�İ취�У�
1.SHChangeNotifyRegister��SHChangeNotify����
2.FindFirstChangeNotification��FindNextChangeNotificationû�б仯�����͡�
3.ReadDirectoryChangesW��ʱ����©��Ϣ�����Խ��ʹ���������,i/o�˿ڣ�CreateIoCompletionPort�����첽���̴߳�ʩ��
4.Change Journal��USN Journal��ֻ����NTFS��REFS�ϡ�
5.�ļ�ϵͳ��������.
6.hook api and messages.
7.�������籸��һ�ݣ����ڵıȽϣ�.
8.ICopyHook�ӿڵĻص�����.
9.������
*/


#pragma once


class Directory
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


#define BUFSIZE MAX_PATH


#define MAX_BUFFER  4096


typedef struct _PER_IO_CONTEXT {//�Զ���ṹ��������ɼ���(���������)
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
