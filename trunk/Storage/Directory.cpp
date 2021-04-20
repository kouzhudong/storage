#include "pch.h"
#include "Directory.h"


#pragma warning(disable:28159)
#pragma warning(disable:4996)
#pragma warning(disable:6001)


//////////////////////////////////////////////////////////////////////////////////////////////////


void ChangingCurrentDirectory(int argc, TCHAR ** argv)
/*
Changing the Current Directory
2018/05/31

The directory at the end of the active path is called the current directory;
it is the directory in which the active application started, unless it has been explicitly changed.
An application can determine which directory is current by calling the GetCurrentDirectory function.
It is sometimes necessary to use the GetFullPathName function to ensure the drive letter is included if the application requires it.

Although each process can have only one current directory,
if the application switches volumes by using the SetCurrentDirectory function,
the system remembers the last current path for each volume (drive letter).
This behavior will manifest itself only when specifying a drive letter without a fully qualified path when changing the current directory point of reference to a different volume.
This applies to either Get or Set operations.

An application can change the current directory by calling the SetCurrentDirectory function.

The following example demonstrates the use of GetCurrentDirectory and SetCurrentDirectory.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/changing-the-current-directory
*/
{
    TCHAR Buffer[BUFSIZE];
    DWORD dwRet;

    if (argc != 2) {
        _tprintf(TEXT("Usage: %s <dir>\n"), argv[0]);
        return;
    }

    dwRet = GetCurrentDirectory(BUFSIZE, Buffer);
    if (dwRet == 0) {
        printf("GetCurrentDirectory failed (%d)\n", GetLastError());
        return;
    }
    if (dwRet > BUFSIZE) {
        printf("Buffer too small; need %d characters\n", dwRet);
        return;
    }

    if (!SetCurrentDirectory(argv[1])) {
        printf("SetCurrentDirectory failed (%d)\n", GetLastError());
        return;
    }
    _tprintf(TEXT("Set current directory to %s\n"), argv[1]);

    if (!SetCurrentDirectory(Buffer)) {
        printf("SetCurrentDirectory failed (%d)\n", GetLastError());
        return;
    }
    _tprintf(TEXT("Restored previous directory (%s)\n"), Buffer);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int ListingFilesInDirectory(int argc, TCHAR * argv[])
/*
Listing the Files in a Directory
2018/05/31

The following example calls FindFirstFile, FindNextFile, and FindClose to list files in a specified directory.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/listing-the-files-in-a-directory
*/
{
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;

    // If the directory is not specified as a command-line argument, print usage.
    if (argc != 2) {
        _tprintf(TEXT("\nUsage: %s <directory name>\n"), argv[0]);
        return (-1);
    }

    // Check that the input path plus 3 is not longer than MAX_PATH.
    // Three characters are for the "\*" plus NULL appended below.

    (void)StringCchLength(argv[1], MAX_PATH, &length_of_arg);

    if (length_of_arg > (MAX_PATH - 3)) {
        _tprintf(TEXT("\nDirectory path is too long.\n"));
        return (-1);
    }

    _tprintf(TEXT("\nTarget directory is %s\n\n"), argv[1]);

    // Prepare string for use with FindFile functions.  First, copy the
    // string to a buffer, then append '\*' to the directory name.

    StringCchCopy(szDir, MAX_PATH, argv[1]);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

    // Find the first file in the directory.
    hFind = FindFirstFile(szDir, &ffd);
    if (INVALID_HANDLE_VALUE == hFind) {
        DisplayErrorBox(TEXT("FindFirstFile"));
        return dwError;
    }

    // List all the files in the directory with some info about them.
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            _tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName);
        } else {
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            _tprintf(TEXT("  %s   %I64d bytes\n"), ffd.cFileName, filesize.QuadPart);
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) {
        DisplayErrorBox(TEXT("FindFirstFile"));
    }

    FindClose(hFind);
    return dwError;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void __cdecl MovingDirectories(int argc, TCHAR * argv[])
/*
Moving Directories
2018/05/31

To move a directory to another location, along with the files and subdirectories contained within it,
call the MoveFileEx, MoveFileWithProgress, or MoveFileTransacted function.
The MoveFileWithProgress function has the same functionality as MoveFileEx,
except that MoveFileWithProgress enables you to specify a callback routine that receives notifications on the progress of the operation.
The MoveFileTransacted function enables you to perform the operation as a transacted operation.

The following example demonstrates the use of the MoveFileEx function with a directory.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/moving-directories
*/
{
    printf("\n");
    if (argc != 3) {
        printf("ERROR:  Incorrect number of arguments\n\n");
        printf("Description:\n");
        printf("  Moves a directory and its contents\n\n");
        printf("Usage:\n");
        _tprintf(TEXT("  %s [source_dir] [target_dir]\n\n"), argv[0]);
        printf("  The target directory cannot exist already.\n\n");
        return;
    }

    // Move the source directory to the target directory location.
    // The target directory must be on the same drive as the source.
    // The target directory cannot already exist.

    if (!MoveFileEx(argv[1], argv[2], MOVEFILE_WRITE_THROUGH)) {
        printf("MoveFileEx failed with error %d\n", GetLastError());
        return;
    } else {
        _tprintf(TEXT("%s has been moved to %s\n"), argv[1], argv[2]);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void RefreshDirectory(LPTSTR);
void RefreshTree(LPTSTR);
void WatchDirectory(LPTSTR);


void WatchDirectoryTest(int argc, TCHAR * argv[])
{
    if (argc != 2) {
        _tprintf(TEXT("Usage: %s <dir>\n"), argv[0]);
        return;
    }

    WatchDirectory(argv[1]);
}


void WatchDirectory(LPTSTR lpDir)
/*
Obtaining Directory Change Notifications
2018/05/31

An application can monitor the contents of a directory and its subdirectories by using change notifications.
Waiting for a change notification is similar to having a read operation pending against a directory and, if necessary, its subdirectories.
When something changes within the directory being watched, the read operation is completed.
For example, an application can use these functions to update a directory listing whenever a file name within the monitored directory changes.

An application can specify a set of conditions that trigger a change notification by using the FindFirstChangeNotification function.
The conditions include changes to file names, directory names, attributes, file size, time of last write, and security.
This function also returns a handle that can be waited on by using the wait functions.
If the wait condition is satisfied, FindNextChangeNotification can be used to provide a notification handle to wait on subsequent changes.
However, these functions do not indicate the actual change that satisfied the wait condition.

Use FindCloseChangeNotification to close the notification handle.

To retrieve information about the specific change as part of the notification, use the ReadDirectoryChangesW function.
This function also enables you to provide a completion routine.

To track changes on a volume, see change journals.

The following example monitors the directory tree for directory name changes.
It also monitors a directory for file name changes.
The example uses the FindFirstChangeNotification function to create two notification handles and the WaitForMultipleObjects function to wait on the handles.
Whenever a directory is created or deleted in the tree, the example should update the entire directory tree.
Whenever a file is created or deleted in the directory, the example should refresh the directory.

 备注
This simplistic example uses the ExitProcess function for termination and cleanup,
but more complex applications should always use proper resource management such as FindCloseChangeNotification where appropriate.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/obtaining-directory-change-notifications
*/
{
    DWORD dwWaitStatus;
    HANDLE dwChangeHandles[2];
    TCHAR lpDrive[4];
    TCHAR lpFile[_MAX_FNAME];
    TCHAR lpExt[_MAX_EXT];

    _tsplitpath_s(lpDir, lpDrive, 4, NULL, 0, lpFile, _MAX_FNAME, lpExt, _MAX_EXT);

    lpDrive[2] = (TCHAR)'\\';
    lpDrive[3] = (TCHAR)'\0';

    // Watch the directory for file creation and deletion. 
    dwChangeHandles[0] = FindFirstChangeNotification(
        lpDir,                         // directory to watch 
        FALSE,                         // do not watch subtree 
        FILE_NOTIFY_CHANGE_FILE_NAME); // watch file name changes 
    if (dwChangeHandles[0] == INVALID_HANDLE_VALUE) {
        printf("\n ERROR: FindFirstChangeNotification function failed.\n");
        ExitProcess(GetLastError());
    }

    // Watch the subtree for directory creation and deletion. 
    dwChangeHandles[1] = FindFirstChangeNotification(
        lpDrive,                       // directory to watch 
        TRUE,                          // watch the subtree 
        FILE_NOTIFY_CHANGE_DIR_NAME);  // watch dir name changes 
    if (dwChangeHandles[1] == INVALID_HANDLE_VALUE) {
        printf("\n ERROR: FindFirstChangeNotification function failed.\n");
        ExitProcess(GetLastError());
    }

    // Make a final validation check on our handles.
    if ((dwChangeHandles[0] == NULL) || (dwChangeHandles[1] == NULL)) {
        printf("\n ERROR: Unexpected NULL from FindFirstChangeNotification.\n");
        ExitProcess(GetLastError());
    }

    // Change notification is set. Now wait on both notification handles and refresh accordingly. 
    while (TRUE) {
        printf("\nWaiting for notification...\n");// Wait for notification.
        dwWaitStatus = WaitForMultipleObjects(2, dwChangeHandles, FALSE, INFINITE);
        switch (dwWaitStatus) {
        case WAIT_OBJECT_0:
            // A file was created, renamed, or deleted in the directory.
            // Refresh this directory and restart the notification.
            RefreshDirectory(lpDir);
            if (FindNextChangeNotification(dwChangeHandles[0]) == FALSE) {
                printf("\n ERROR: FindNextChangeNotification function failed.\n");
                ExitProcess(GetLastError());
            }
            break;
        case WAIT_OBJECT_0 + 1:
            // A directory was created, renamed, or deleted.
            // Refresh the tree and restart the notification.
            RefreshTree(lpDrive);
            if (FindNextChangeNotification(dwChangeHandles[1]) == FALSE) {
                printf("\n ERROR: FindNextChangeNotification function failed.\n");
                ExitProcess(GetLastError());
            }
            break;
        case WAIT_TIMEOUT:
            // A timeout occurred, this would happen if some value other 
            // than INFINITE is used in the Wait call and no changes occur.
            // In a single-threaded environment you might not want an INFINITE wait.
            printf("\nNo changes in the timeout period.\n");
            break;
        default:
            printf("\n ERROR: Unhandled dwWaitStatus.\n");
            ExitProcess(GetLastError());
            break;
        }
    }
}


void RefreshDirectory(LPTSTR lpDir)
{
    // This is where you might place code to refresh your
    // directory listing, but not the subtree because it would not be necessary.

    _tprintf(TEXT("Directory (%s) changed.\n"), lpDir);
}


void RefreshTree(LPTSTR lpDrive)
{
    // This is where you might place code to refresh your directory listing, including the subtree.

    _tprintf(TEXT("Directory tree (%s) changed.\n"), lpDrive);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int DirectoryChange(int argc, _TCHAR * argv[])
/*
目录监控的最简单示例：ReadDirectoryChangesW的用法。
*/
{
    setlocale(LC_CTYPE, ".936");

    int  nBufferSize = 1024;
    char * buffer = new char[nBufferSize];

    HANDLE hDirectoryHandle = CreateFile(L"e:\\test",
                                         FILE_LIST_DIRECTORY,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         0,
                                         OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                         0);
    if (!hDirectoryHandle)
        return 0;

    while (1) {
        memset(buffer, 0, nBufferSize);

        DWORD dwBytes = 0;
        DWORD dwNotifyFilter =
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_CREATION |
            FILE_NOTIFY_CHANGE_SIZE;

        if (!ReadDirectoryChangesW(hDirectoryHandle,
                                   buffer,
                                   nBufferSize,
                                   1,
                                   dwNotifyFilter,
                                   &dwBytes,
                                   NULL,
                                   NULL) ||
            GetLastError() == ERROR_INVALID_HANDLE) {
            break;
        }

        if (!dwBytes) {
            printf("Buffer overflow\r\n");
        }

        PFILE_NOTIFY_INFORMATION record = (PFILE_NOTIFY_INFORMATION)buffer;
        DWORD cbOffset = 0;

        do {
            switch (record->Action) {
            case FILE_ACTION_ADDED:
                printf("添加:");
                break;
            case FILE_ACTION_REMOVED:
                printf("移除:");
                break;
            case FILE_ACTION_MODIFIED:
                printf("修改:");
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
                printf("旧名字:");
                break;
            case FILE_ACTION_RENAMED_NEW_NAME:
                printf("新名字:");
                break;
            default:
                break;
            }

            wprintf(record->FileName); printf("\r\n");

            cbOffset = record->NextEntryOffset;
            record = (PFILE_NOTIFY_INFORMATION)((LPBYTE)record + cbOffset);
        } while (cbOffset);
    }

    delete[] buffer;

    if (hDirectoryHandle)
        CloseHandle(hDirectoryHandle);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


PER_IO_CONTEXT g_pIContext[9];


DWORD WINAPI DirectoryChangeThread(LPVOID lpParam)
{
    PPER_IO_CONTEXT pic = (PPER_IO_CONTEXT)lpParam;

    while (true) {
        DWORD dwBytes;
        PPER_IO_CONTEXT pIContext = NULL;
        LPOVERLAPPED pOL = NULL;

        if (GetQueuedCompletionStatus(pic->hIocp, &dwBytes, (PULONG_PTR)&pIContext, &pOL, INFINITE))
        {
            if (NULL == pIContext) {
                return 0;
            }

            PFILE_NOTIFY_INFORMATION pfi = (PFILE_NOTIFY_INFORMATION)pIContext->lpBuffer;
            DWORD cbOffset;

            do {
                switch (pfi->Action) {
                case FILE_ACTION_ADDED:
                    printf("添加:");
                    break;
                case FILE_ACTION_REMOVED:
                    printf("移除:");
                    break;
                case FILE_ACTION_MODIFIED:
                    printf("修改:");
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    printf("旧名字:");
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    printf("新名字:");
                    break;
                default:
                    break;
                }
                wprintf(pfi->FileName);
                printf("\r\n");

                cbOffset = pfi->NextEntryOffset;//一次消息中包含了多个文件变化的信息吗？
                pfi = (PFILE_NOTIFY_INFORMATION)((LPBYTE)pfi + cbOffset);
            } while (cbOffset);
        }

        DWORD nBytes = 0;
        ReadDirectoryChangesW(
            pic->hDir,
            pic->lpBuffer,
            MAX_BUFFER,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE,
            &nBytes,
            (LPOVERLAPPED)pic,
            NULL);
    }
}


void DirectoryChangeUseIOCP()
{
    setlocale(LC_CTYPE, ".936");

    lstrcpy(g_pIContext[0].lpszDirName, L"e:\\test");
    lstrcpy(g_pIContext[1].lpszDirName, L"c:\\temp");

    for (int i = 0; i < 9; i++) {
        if (lstrlen(g_pIContext[i].lpszDirName) == 0) {
            break;
        }

        g_pIContext[i].hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        g_pIContext[i].hDir = CreateFile(g_pIContext[i].lpszDirName,
                                         FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         NULL,
                                         OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                         NULL);
        CreateIoCompletionPort(g_pIContext[i].hDir, g_pIContext[i].hIocp, (ULONG_PTR)&g_pIContext[i], 0);

        HANDLE hThread = CreateThread(NULL, 0, DirectoryChangeThread, &g_pIContext[i], 0, NULL);//可以创建多个，如CPU个数的两倍。
        _ASSERTE(hThread);
        CloseHandle(hThread);

        DWORD nBytes = 0;
        BOOL  bRet = FALSE;
        bRet = ReadDirectoryChangesW(
            g_pIContext[i].hDir,
            g_pIContext[i].lpBuffer,
            MAX_BUFFER,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_SIZE,//这个不会重复。FILE_NOTIFY_CHANGE_LAST_WRITE会重复。
            &nBytes,
            (LPOVERLAPPED)&g_pIContext[i],
            NULL);
    }

    for (;;) {
        SleepEx(INFINITE, TRUE);
    }

    //等待线程结束的代码还要加上。

    for (int i = 0; i < 9; i++) {
        PostQueuedCompletionStatus(g_pIContext[i].hIocp, 0, NULL, NULL);
        CloseHandle(g_pIContext[i].hIocp);
        CloseHandle(g_pIContext[i].hDir);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//#define MAX_BUFFER  8192


DIRECTORY_INFO  DirInfo[MAX_DIRS];


VOID CALLBACK DirectoryChangesCompletionRoutine(DWORD dwErrorCode,
                                                DWORD dwNumberOfBytesTransfered,
                                                LPOVERLAPPED lpOverlapped)
{
    for (int i = 0; ; i++) {
        if (DirInfo[i].hDir == NULL) {
            break;
        }

        //看看哪个监控目录发生变化了。
        if (DirInfo[i].Overlapped.Internal == lpOverlapped->Internal &&
            DirInfo[i].Overlapped.InternalHigh == lpOverlapped->InternalHigh) {
            DWORD cbOffset;
            PFILE_NOTIFY_INFORMATION fni;
            WCHAR FileName[MAX_PATH] = {0};
            wchar_t FullPathName[MAX_PATH] = {0};

            fni = (PFILE_NOTIFY_INFORMATION)DirInfo[i].lpBuffer;

            do {
                cbOffset = fni->NextEntryOffset;

                switch (fni->Action) {
                case FILE_ACTION_ADDED:
                    wprintf(L"ADDED: ");
                    break;
                case FILE_ACTION_MODIFIED:
                    wprintf(L"MODIFIED: ");//有重复会两次。
                    break;
                default: wprintf(L"unknown event: ");
                    break;
                }

                (void)lstrcpyn(FileName, fni->FileName, fni->FileNameLength / sizeof(WCHAR) + 1);
                FileName[fni->FileNameLength / sizeof(WCHAR) + 1] = '\0';

                lstrcpy(FullPathName, DirInfo[i].lpszDirName);
                PathAppend(FullPathName, FileName);

                wprintf(L"%s\n", FullPathName);

                fni = (PFILE_NOTIFY_INFORMATION)((LPBYTE)fni + cbOffset);
            } while (cbOffset);

            RtlZeroMemory(DirInfo[i].lpBuffer, MAX_BUFFER);
            DirInfo[i].dwBufLength = 0;
            DirInfo[i].Overlapped.Internal = 0;
            DirInfo[i].Overlapped.InternalHigh = 0;
            DirInfo[i].Overlapped.Offset = 0;
            DirInfo[i].Overlapped.OffsetHigh = 0;
            DirInfo[i].Overlapped.Pointer = 0;
            DirInfo[i].Overlapped.hEvent = 0;

            BOOL B = ReadDirectoryChangesW(
                DirInfo[i].hDir,
                DirInfo[i].lpBuffer,
                MAX_BUFFER,
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &DirInfo[i].dwBufLength,
                &DirInfo[i].Overlapped,
                DirectoryChangesCompletionRoutine);
            _ASSERTE(B);

            break;
        }
    }
}


int CreateDirectoryChangeThread()
/*
支持ReadDirectoryChangesW异步的，CompletionRoutine，且多目录的。
*/
{
    lstrcpy(DirInfo[0].lpszDirName, L"e:\\test");
    lstrcpy(DirInfo[1].lpszDirName, L"c:\\temp");

    for (int i = 0; ; i++) {
        if (lstrlen(DirInfo[i].lpszDirName) == 0) {
            break;
        }

        DirInfo[i].hDir = CreateFile(
            DirInfo[i].lpszDirName,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL);
        _ASSERTE(DirInfo[i].hDir != INVALID_HANDLE_VALUE);
    }

    for (int i = 0; ; i++) {
        if (DirInfo[i].hDir == NULL) {
            break;
        }

        BOOL B = ReadDirectoryChangesW(
            DirInfo[i].hDir,
            DirInfo[i].lpBuffer,
            MAX_BUFFER,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &DirInfo[i].dwBufLength,
            &DirInfo[i].Overlapped,
            DirectoryChangesCompletionRoutine);
        _ASSERTE(B);
    }

    for (; ; ) {
        SleepEx(INFINITE, TRUE);
    }

    for (int i = 0; ; i++) {
        if (DirInfo[i].hDir == 0) {
            break;
        }

        CloseHandle(DirInfo[i].hDir);
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


HWND GetConsoleHwnd(void)
{
    HWND hwndFound;         // This is what is returned to the caller.
    char pszNewWindowTitle[MY_BUFSIZE]; // Contains fabricated WindowTitle.
    char pszOldWindowTitle[MY_BUFSIZE]; // Contains original WindowTitle.

    GetConsoleTitleA(pszOldWindowTitle, MY_BUFSIZE);// Fetch current window title.
    wsprintfA(pszNewWindowTitle, "%d/%d", GetTickCount(), GetCurrentProcessId());// Format a "unique" NewWindowTitle.
    SetConsoleTitleA(pszNewWindowTitle);// Change current window title.
    Sleep(40);// Ensure window title has been updated.
    hwndFound = FindWindowA(NULL, pszNewWindowTitle);// Look for NewWindowTitle.
    SetConsoleTitleA(pszOldWindowTitle);// Restore original window title.
    return(hwndFound);
}


void MoveWindowToBottomMostRightCorner(void)
{
    // Different monitor display devices. 
    // Assuming a maximum of 4 to be present. 
    const char * displayDevice[4] = {
        "\\\\.\\DISPLAY1",
        "\\\\.\\DISPLAY2",
        "\\\\.\\DISPLAY3",
        "\\\\.\\DISPLAY4"
    };

    DEVMODEA dev;
    dev.dmSize = sizeof(DEVMODE);

    int success = 0;
    int i = 0;
    while (!success && i < 4) {
        success = EnumDisplaySettingsA(displayDevice[i], ENUM_CURRENT_SETTINGS, &dev);
        i++;
    }

    HWND hwnd = GetConsoleHwnd();

    if (success) {
        MoveWindow(hwnd,
                   dev.dmPelsWidth - SCREEN_RELATIVE_WIDTH_DIFFERNCE,
                   dev.dmPelsHeight - SCREEN_RELATIVE_HEIGHT_DIFFERENCE,
                   WINDOW_WIDTH,
                   WINDOW_HEIGHT,
                   TRUE);
    }
}


char path[1024] = "\\\\lxmmc01\\share";
char listnCmd[1024] = "c:\\lxm\\DirContDiff.exe \"";


int suspend = 0;


void SuspendListen(int arg)
{
    signal(SIGINT, SuspendListen);
    suspend = !suspend;
    if (suspend) {
        system("cls");
        printf("\n ** DirListener.exe By Raghavan Santhanam for videos **");
        printf("\n Press Ctrl+C to pause or run.\n");
        printf("\r Paused.");
    }
}


void WaitUntilNextChange(void)
{
    HANDLE h = FindFirstChangeNotificationA(path, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE);
    if (h != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(h, INFINITE);
    }
}


int NoNewFilesPresent(void)
{
    FILE * fp = fopen("c:\\lxm\\new.txt", "r");
    if (fp != NULL) {
        fclose(fp);
    }

    return fp == NULL;
}


int IsValidPath(char * path)
{
    char curDir[1024] = "";
    GetCurrentDirectoryA(1023, curDir);
    int validPath = SetCurrentDirectoryA(path);
    if (validPath) {
        SetCurrentDirectoryA(curDir); // Reverting back to the original.
    }

    return validPath;
}


int DirListener(int argc, char * argv[])
/*
 * File : DirListener.c
 * Author : Raghavan Santhanam
 * Date : 23 / 06 / 2011
 *
 *    No copyrights. You are free to do anything with this code.
 *    Happy "C" programming!!
 */
{
    MoveWindowToBottomMostRightCorner();
    printf("\n ** DirListener.exe By Raghavan Santhanam for videos **");
    printf("\n Press Ctrl+C to pause or run.\n ");
    signal(SIGINT, SuspendListen);

    // Clean up the files used by DirContDiff.c
    system("del c:\\lxm\\new1.txt > NUL 2> NUL && del c:\\lxm\\new2.txt > NUL 2> NUL && "
           "del c:\\lxm\\new.txt > NUL 2> NUL");

    if (argc == 1) {
        if (!IsValidPath(path)) {
            printf("\n\n Invalid Path(Directory) : %s", path);
            Sleep(5000);
            goto done;
        }
    } else if (argc == 2) {
        char * p = argv[1];
        if (p[strlen(p) - 1] == '\\') {
            printf("\n Path : %s. Remove trailing slash and try again.", path);
            goto done;
        }
        if (!IsValidPath(argv[1])) {
            printf("\n Invalid Path(Directory) : %s", path);
            goto done;
        }
        strcpy(path, argv[1]);
    } else {
        printf("\n Maximum number of command-line arguments : 1. \n You can give a path as the only argument.");
        goto done;
    }

    strcat(listnCmd, path);
    strcat(listnCmd, "\"");

    // Loop and wait asynchronously for a change under the specified path.
    while (1) {
        if (!suspend) {
            system("cls");
            printf("\n ** DirListener.exe By Raghavan Santhanam for videos **");
            printf("\n Press Ctrl+C to pause or run.\n");
            system(listnCmd);
        }

        // Since, the term "New" is relative to the contents
        // of latest1.txt when present which can be created
        // either by NOTIFY_lxm or DirListener(in mouse hover recognition), we would check new.txt to be present
        // to display the appropriate message until the next
        // change. Displaying the other message in case of any new videos is being taken care of by DirContDiff.exe
        if (NoNewFilesPresent()) {
            printf("\r No new videos @ %s!", path);
        }

        // It is important to note that there can be a change
        // but that change need not be an addition of new
        // video. So, we have to compare the directory listnings
        // anyhow.           
        WaitUntilNextChange();

        // There could be file changes every single second.
        // But, let's be fair enough to other processes running in the system and thereby caring CPU for it's health :)
        Sleep(1000);
    }

done:
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
