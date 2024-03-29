#include "pch.h"
#include "Link.h"
#include "File.h"
//#include <ntstatus.h>

//\Windows Kits\10\Include\10.0.22621.0\shared\ntstatus.h
#define STATUS_BUFFER_OVERFLOW           ((NTSTATUS)0x80000005L)


//////////////////////////////////////////////////////////////////////////////////////////////////


void CreateHardLinkTest()
/*
题目：硬链接的创建。

Establishes a hard link between an existing file and a new file.
This function is only supported on the NTFS file system, and only for files, not directories.

To perform this operation as a transacted operation, use the CreateHardLinkTransacted function.

The maximum number of hard links that can be created with this function is 1023 per file.
If more than 1023 links are created for a file, an error results.

Any directory entry for a file that is created with CreateFile or CreateHardLink is a hard link to an associated file.
An additional hard link that is created with the CreateHardLink function allows you to have multiple directory entries for a file, 
that is, multiple hard links to the same file, which can be different names in the same directory, 
or the same or different names in different directories.
However, all hard links to a file must be on the same volume.

The security descriptor belongs to the file to which a hard link points.
The link itself is only a directory entry, and does not have a security descriptor.
Therefore, when you change the security descriptor of a hard link, 
you a change the security descriptor of the underlying file, 
and all hard links that point to the file allow the newly specified access.
You cannot give a file different security descriptors on a per-hard-link basis.

This function does not modify the security descriptor of the file to be linked to, 
even if security descriptor information is passed in the lpSecurityAttributes parameter.

硬链接有创建和删除，但是查询还得自己写。

其实：
硬链接的创建就是NtOpenFile+NtSetInformationFile(FileLinkInformation);这个在驱动中写个函数：ZwCreateHardLink。
硬链接的删除呢？以后再分析吧！

made by correy
made at 2015.09.26
homepage:http://correy.webs.com
*/
{
    DWORD d = 0;

    //The name of the new file.This parameter cannot specify the name of a directory.
    LPCTSTR pszNewLinkName = L"f:\\HardLink.txt"; //必须是不存在的文件或硬链接。   

    //The name of the existing file.This parameter cannot specify the name of a directory.
    LPCTSTR pszExistingFileName = L"f:\\test.txt";//已经存在的文件。

    //Reserved; must be NULL.说是这样说了，逆向代码还是设置了。
    //LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;

    BOOL fCreatedLink = CreateHardLink(pszNewLinkName, pszExistingFileName, NULL);
    if (fCreatedLink == FALSE) {
        d = GetLastError();//0x000000B7:当文件已存在时，无法创建该文件。 
    }

    MessageBox(0, L"请检查！", L"硬链接创建成功！", 0);

    //只删除硬链接，并没有删除实际的文件。
    fCreatedLink = DeleteFile(pszNewLinkName);
    if (fCreatedLink == FALSE) {
        d = GetLastError();
    }
}


int WINAPI HardLinkTest()
/************************************************************
Module name: FileLink.cpp
Written by: Jeffrey Richter
Notices: Copyright (c) 1998 Jeffrey Richter
************************************************************/
{
    if (__argc != 3) {
        TCHAR sz[200];
        wsprintf(sz,
                 __TEXT("FileLink creates a hard link to an existing file.\n")
                 __TEXT("Usage: %s  (ExistingFile)  (NewFileName)"), \
                 __targv[0]);
        MessageBox(NULL, sz,
                   __TEXT("FileLink by Jeffrey Richter"),
                   MB_ICONINFORMATION | MB_OK);
        return(0);
    }

    if (!CreateHardLink(__targv[2], __targv[1], NULL)) {
        MessageBox(NULL, __TEXT("The FileLink couldn't be created.\n"),
                   __TEXT("FileLink by Jeffrey Richter"),
                   MB_ICONINFORMATION | MB_OK);
    }

    return(0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


HRESULT CreateLink(LPCWSTR lpszPathObj, LPCSTR lpszPathLink, LPCWSTR lpszDesc)
/*
// CreateLink - Uses the Shell's IShellLink and IPersistFile interfaces
//              to create and store a shortcut to the specified object.
//
// Returns the result of calling the member functions of the interfaces.
//
// Parameters:
// lpszPathObj  - Address of a buffer that contains the path of the object,
//                including the file name.
// lpszPathLink - Address of a buffer that contains the path where the
//                Shell link is to be stored, including the file name.
// lpszDesc     - Address of a buffer that contains a description of the
//                Shell link, stored in the Comment field of the link
//                properties.

Creating a Shortcut and a Folder Shortcut to a File

The CreateLink sample function in the following example creates a shortcut.
The parameters include a pointer to the name of the file to link to,
a pointer to the name of the shortcut that you are creating, and a pointer to the description of the link.
The description consists of the string, "Shortcut to file name," where file name is the name of the file to link to.

To create a folder shortcut using the CreateLink sample function, call CoCreateInstance using CLSID_FolderShortcut,
instead of CLSID_ShellLink (CLSID_FolderShortcut supports IShellLink).
All other code remains the same.

Because CreateLink calls the CoCreateInstance function, it is assumed that the CoInitialize function has already been called.
CreateLink uses the IPersistFile interface to save the shortcut and the IShellLink interface to store the file name and description.

https://docs.microsoft.com/en-us/windows/win32/shell/links
*/
{
    HRESULT hres;
    IShellLink * psl;

    (void)CoInitialize(0);

    // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
    // has already been called.
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID *)&psl);
    if (SUCCEEDED(hres)) {
        IPersistFile * ppf;

        // Set the path to the shortcut target and add the description. 
        psl->SetPath(lpszPathObj);
        psl->SetDescription(lpszDesc);

        // Query IShellLink for the IPersistFile interface, used for saving the 
        // shortcut in persistent storage. 
        hres = psl->QueryInterface(IID_IPersistFile, (LPVOID *)&ppf);
        if (SUCCEEDED(hres)) {
            WCHAR wsz[MAX_PATH];

            // Ensure that the string is Unicode. 
            MultiByteToWideChar(CP_ACP, 0, lpszPathLink, -1, wsz, MAX_PATH);

            // Add code here to check return value from MultiByteWideChar 
            // for success.

            // Save the link by calling IPersistFile::Save. 
            hres = ppf->Save(wsz, TRUE);
            ppf->Release();
        }

        psl->Release();
    }

    CoUninitialize();

    return hres;
}


HRESULT ResolveIt(HWND hwnd, LPCSTR lpszLinkFile, LPWSTR lpszPath, int iPathBufferSize)
/*
// ResolveIt - Uses the Shell's IShellLink and IPersistFile interfaces
//             to retrieve the path and description from an existing shortcut.
//
// Returns the result of calling the member functions of the interfaces.
//
// Parameters:
// hwnd         - A handle to the parent window. The Shell uses this window to
//                display a dialog box if it needs to prompt the user for more
//                information while resolving the link.
// lpszLinkFile - Address of a buffer that contains the path of the link,
//                including the file name.
// lpszPath     - Address of a buffer that receives the path of the link
//                target, including the file name.
// lpszDesc     - Address of a buffer that receives the description of the
//                Shell link, stored in the Comment field of the link
//                properties.

Resolving a Shortcut
An application may need to access and manipulate a shortcut that was previously created.
This operation is referred to as resolving the shortcut.

The application-defined ResolveIt function in the following example resolves a shortcut.
Its parameters include a window handle, a pointer to the path of the shortcut,
and the address of a buffer that receives the new path to the object.
The window handle identifies the parent window for any message boxes that the Shell may need to display.
For example, the Shell can display a message box if the link is on unshared media,
if network problems occur, if the user needs to insert a floppy disk, and so on.

The ResolveIt function calls the CoCreateInstance function and assumes that the CoInitialize function has already been called.
Note that ResolveIt needs to use the IPersistFile interface to store the link information.
IPersistFile is implemented by the IShellLink object.
The link information must be loaded before the path information is retrieved, which is shown later in the example.
Failing to load the link information causes the calls to the IShellLink::GetPath and IShellLink::GetDescription member functions to fail.

https://docs.microsoft.com/en-us/windows/win32/shell/links
*/
{
    HRESULT hres;
    IShellLink * psl;
    WCHAR szGotPath[MAX_PATH];
    WCHAR szDescription[MAX_PATH];
    WIN32_FIND_DATA wfd = {0};

    (void)CoInitialize(0);

    *lpszPath = 0; // Assume failure 

    // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
    // has already been called. 
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID *)&psl);
    if (SUCCEEDED(hres)) {
        IPersistFile * ppf;

        // Get a pointer to the IPersistFile interface. 
        hres = psl->QueryInterface(IID_IPersistFile, (void **)&ppf);
        if (SUCCEEDED(hres)) {
            WCHAR wsz[MAX_PATH];

            // Ensure that the string is Unicode. 
            MultiByteToWideChar(CP_ACP, 0, lpszLinkFile, -1, wsz, MAX_PATH);

            // Add code here to check return value from MultiByteWideChar 
            // for success.

            // Load the shortcut. 
            hres = ppf->Load(wsz, STGM_READ);
            if (SUCCEEDED(hres)) {
                // Resolve the link. 
                hres = psl->Resolve(hwnd, 0);
                if (SUCCEEDED(hres)) {
                    // Get the path to the link target. 
                    hres = psl->GetPath(szGotPath, MAX_PATH, (WIN32_FIND_DATA *)&wfd, SLGP_SHORTPATH);
                    if (SUCCEEDED(hres)) {
                        // Get the description of the target. 
                        hres = psl->GetDescription(szDescription, MAX_PATH);
                        if (SUCCEEDED(hres)) {
                            hres = StringCbCopy(lpszPath, iPathBufferSize, szGotPath);
                            if (SUCCEEDED(hres)) {
                                // Handle success
                            } else {
                                // Handle the error
                            }
                        }
                    }
                }
            }

            // Release the pointer to the IPersistFile interface. 
            ppf->Release();
        }

        // Release the pointer to the IShellLink interface. 
        psl->Release();
    }

    CoUninitialize();

    return hres;
}


int CreateLinkTest()
{
    wchar_t lpszPathObj[MAX_PATH] = L"C:\\Windows\\regedit.exe";//可以为文件也可以为文件夹
    char lnk[MAX_PATH] = "c:\\regedit.lnk";//这里的后缀名必须是.lnk，无后缀名或者改为url等其他的都不行。
    CreateLink(lpszPathObj, lnk, L"made by correy");

    wchar_t temp[MAX_PATH] = {0};
    ResolveIt(NULL, lnk, temp, sizeof(temp));

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void DisplayFileHardLinkInformation(PFILE_LINK_ENTRY_INFORMATION Entry, PWCHAR Volume)
{
    wstring HardLinkName;

    //printf("ParentFileId:%llx, FileName:%ls.\r\n", Entry->ParentFileId, Entry->FileName);

    //OpenFileById根据FileId获取文件的路径。
    HANDLE hFile = OpenFileByFileId(Volume, Entry->ParentFileId);

    HardLinkName = Volume;

    DisplayNameInfo(hFile, HardLinkName);

    const wchar_t * p = HardLinkName.c_str();
    if (p[HardLinkName.size() - 1] != '\\') {
        HardLinkName += L"\\";//根目录下不需要这个。
    }

    HardLinkName += Entry->FileName;//盘符，父路径，文件名，三者拼接成完整的路径。

    CloseHandle(hFile);

    FILE_ID_INFO FileIdInformation{};
    GetFileIdInfo(HardLinkName, FileIdInformation);

    //输出类似于：fsutil.exe file queryFileID c:\windows\notepad.exe
    printf("FileId:%016llx%016llx, FileName:%ls.\r\n",
           *(PULONGLONG)&FileIdInformation.FileId.Identifier[8],
           *(PULONGLONG)FileIdInformation.FileId.Identifier,
           HardLinkName.c_str());
}


EXTERN_C
__declspec(dllexport)
void WINAPI GetFileHardLinkInformation(IN LPCWSTR FileName)
/*
参数的形式为:L"\\DosDevices\\C:\\Windows\\notepad.exe"

谨记：硬链接不止一个。

https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_links_information
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING ObjectName = {0};    
    OBJECT_ATTRIBUTES ob{};
    HANDLE FileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    FILE_LINKS_INFORMATION LinksInfo{};
    PFILE_LINKS_INFORMATION FileInformation = nullptr;

    __try {
        if (!g_NtOpenFile || !NtQueryInformationFile || !g_NtClose) {

            __leave;
        }

        ObjectName.Buffer = (PWSTR)FileName;
        ObjectName.Length = (USHORT)wcslen(FileName) * sizeof(WCHAR);
        ObjectName.MaximumLength = ObjectName.Length;
        InitializeObjectAttributes(&ob, &ObjectName, OBJ_CASE_INSENSITIVE, 0, 0);
        Status = g_NtOpenFile(&FileHandle,
                            GENERIC_READ | SYNCHRONIZE,
                            &ob,
                            &IoStatusBlock,
                            FILE_SHARE_READ,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(Status)) {

            __leave;
        }

        Status = NtQueryInformationFile(FileHandle,
                                        &IoStatusBlock,
                                        &LinksInfo,
                                        sizeof(FILE_LINKS_INFORMATION),
                                        (FILE_INFORMATION_CLASS)46);//FileHardLinkInformation (46)
        //_ASSERTE(STATUS_BUFFER_OVERFLOW == Status);//成功了也继续申请内存。

        /*
        If the member EntriesReturned has a value of 0, there is not enough available memory to return an entry. 
        The error STATUS_BUFFER_OVERFLOW (0x80000005) indicates that not all available entries were returned.
        */
        FileInformation = (PFILE_LINKS_INFORMATION)
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LinksInfo.BytesNeeded);
        if (!FileInformation) {

            __leave;
        }

        Status = NtQueryInformationFile(FileHandle,
                                        &IoStatusBlock,
                                        FileInformation,
                                        LinksInfo.BytesNeeded,
                                        (FILE_INFORMATION_CLASS)46);//FileHardLinkInformation (46)
        if (!NT_SUCCESS(Status)) {

            __leave;
        }

        if (FileInformation->EntriesReturned <= 1) {
            //printf("FileName:%ls 没有硬链接.\r\n", FileName);
            __leave;
        }

        /*
        The member Entry is the first FILE_LINK_ENTRY_INFORMATION structure in a list of entries.
        Each entry is located sizeof(FILE_LINK_ENTRY_INFORMATION) + ((FileNameLength - 1 ) * sizeof(WCHAR)) from the previous entry when the FileNameLength member of FILE_LINK_ENTRY_INFORMATION > 1. 
        Otherwise, each entry is located sizeof(FILE_LINK_ENTRY_INFORMATION) from the previous entry.

        这个办法是错误的，因为FILE_LINK_ENTRY_INFORMATION结构是有隐含的对齐的。
        2023/5/17
        */
        
        PFILE_LINK_ENTRY_INFORMATION Entry = &FileInformation->Entry;
        for (; ; Entry = (PFILE_LINK_ENTRY_INFORMATION)(((PBYTE)Entry + Entry->NextEntryOffset))) {
            WCHAR Tmp[8]{};
            Tmp[0] = FileName[12];
            Tmp[1] = FileName[13];
            //Tmp[2] = FileName[14];

            DisplayFileHardLinkInformation(Entry, Tmp);

            if (0 == Entry->NextEntryOffset) {
                break;
            }
        }

        //Entry = &FileInformation->Entry;
        //for (ULONG i = 0; i < FileInformation->EntriesReturned; i++) {
        //    printf("ParentFileId:%llx, FileName:%ls.\r\n", Entry->ParentFileId, Entry->FileName);
        //    Entry = (PFILE_LINK_ENTRY_INFORMATION)(((PBYTE)Entry + sizeof(FILE_LINK_ENTRY_INFORMATION) + ((Entry->FileNameLength - 1) * sizeof(WCHAR))));
        //}
    } __finally {  
        if (FileInformation) {
            HeapFree(GetProcessHeap(), 0, FileInformation);
        }

        if (FileHandle) {
            Status = g_NtClose(FileHandle);
            if (!NT_SUCCESS(Status)) {
                 
            }
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI GetFileReparsePointInformation(IN LPCWSTR FileName)
/*

未完成的测试。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    FILE_REPARSE_POINT_INFORMATION ReparsePointInfo{};
    HANDLE hFile = INVALID_HANDLE_VALUE;

    __try {
        if (!NtQueryInformationFile) {

            __leave;
        }

        hFile = CreateFile(FileName,
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "FILE:%s, LINE:%d, LastError:%d, FileName:%ls.\r\n",
                    __FILE__, __LINE__, GetLastError(), FileName);//1920
            __leave;
        }

        Status = NtQueryInformationFile(hFile,
                                        &IoStatusBlock,
                                        &ReparsePointInfo,
                                        sizeof(FILE_REPARSE_POINT_INFORMATION),
                                        (FILE_INFORMATION_CLASS)33);//FileReparsePointInformation



    } __finally {
        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
