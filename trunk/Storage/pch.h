// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#pragma once


// 添加要在此处预编译的标头
#include "framework.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502
#endif

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define myheapalloc(x) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, x))
#define myheapfree(x)  (HeapFree(GetProcessHeap(), 0, x))

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef BOOL(WINAPI * LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

typedef DWORD(*PeCallBack)(_In_ PBYTE Data, _In_ DWORD Size, _In_opt_ PVOID Context);//回调函数的原型。

typedef BOOL(WINAPI * SetSecurityDescriptorControlFnPtr)(IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                                         IN SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
                                                         IN SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet);

//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef _FILE_INFORMATION_CLASS
#undef _FILE_INFORMATION_CLASS //\Windows Kits\10\Include\10.0.22621.0\um\winternl.h只定义一个值。
#endif


// C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\km\wdm.h
// Define the file information class values
//
// WARNING:  The order of the following values are assumed by the I/O system.
//           Any changes made here should be reflected there as well.
//


//typedef enum _FILE_INFORMATION_CLASS //已经有#undef _FILE_INFORMATION_CLASS了，还出现：重定义。
//{
//    FileDirectoryInformation = 1,
//    FileFullDirectoryInformation,                   // 2
//    FileBothDirectoryInformation,                   // 3
//    FileBasicInformation,                           // 4
//    FileStandardInformation,                        // 5
//    FileInternalInformation,                        // 6
//    FileEaInformation,                              // 7
//    FileAccessInformation,                          // 8
//    FileNameInformation,                            // 9
//    FileRenameInformation,                          // 10
//    FileLinkInformation,                            // 11
//    FileNamesInformation,                           // 12
//    FileDispositionInformation,                     // 13
//    FilePositionInformation,                        // 14
//    FileFullEaInformation,                          // 15
//    FileModeInformation,                            // 16
//    FileAlignmentInformation,                       // 17
//    FileAllInformation,                             // 18
//    FileAllocationInformation,                      // 19
//    FileEndOfFileInformation,                       // 20
//    FileAlternateNameInformation,                   // 21
//    FileStreamInformation,                          // 22
//    FilePipeInformation,                            // 23
//    FilePipeLocalInformation,                       // 24
//    FilePipeRemoteInformation,                      // 25
//    FileMailslotQueryInformation,                   // 26
//    FileMailslotSetInformation,                     // 27
//    FileCompressionInformation,                     // 28
//    FileObjectIdInformation,                        // 29
//    FileCompletionInformation,                      // 30
//    FileMoveClusterInformation,                     // 31
//    FileQuotaInformation,                           // 32
//    FileReparsePointInformation,                    // 33
//    FileNetworkOpenInformation,                     // 34
//    FileAttributeTagInformation,                    // 35
//    FileTrackingInformation,                        // 36
//    FileIdBothDirectoryInformation,                 // 37
//    FileIdFullDirectoryInformation,                 // 38
//    FileValidDataLengthInformation,                 // 39
//    FileShortNameInformation,                       // 40
//    FileIoCompletionNotificationInformation,        // 41
//    FileIoStatusBlockRangeInformation,              // 42
//    FileIoPriorityHintInformation,                  // 43
//    FileSfioReserveInformation,                     // 44
//    FileSfioVolumeInformation,                      // 45
//    FileHardLinkInformation,                        // 46
//    FileProcessIdsUsingFileInformation,             // 47
//    FileNormalizedNameInformation,                  // 48
//    FileNetworkPhysicalNameInformation,             // 49
//    FileIdGlobalTxDirectoryInformation,             // 50
//    FileIsRemoteDeviceInformation,                  // 51
//    FileUnusedInformation,                          // 52
//    FileNumaNodeInformation,                        // 53
//    FileStandardLinkInformation,                    // 54
//    FileRemoteProtocolInformation,                  // 55
//
//        //
//        //  These are special versions of these operations (defined earlier)
//        //  which can be used by kernel mode drivers only to bypass security
//        //  access checks for Rename and HardLink operations.  These operations
//        //  are only recognized by the IOManager, a file system should never
//        //  receive these.
//        //
//
//        FileRenameInformationBypassAccessCheck,         // 56
//        FileLinkInformationBypassAccessCheck,           // 57
//
//            //
//            // End of special information classes reserved for IOManager.
//            //
//
//            FileVolumeNameInformation,                      // 58
//            FileIdInformation,                              // 59
//            FileIdExtdDirectoryInformation,                 // 60
//            FileReplaceCompletionInformation,               // 61
//            FileHardLinkFullIdInformation,                  // 62
//            FileIdExtdBothDirectoryInformation,             // 63
//            FileDispositionInformationEx,                   // 64
//            FileRenameInformationEx,                        // 65
//            FileRenameInformationExBypassAccessCheck,       // 66
//            FileDesiredStorageClassInformation,             // 67
//            FileStatInformation,                            // 68
//            FileMemoryPartitionInformation,                 // 69
//            FileStatLxInformation,                          // 70
//            FileCaseSensitiveInformation,                   // 71
//            FileLinkInformationEx,                          // 72
//            FileLinkInformationExBypassAccessCheck,         // 73
//            FileStorageReserveIdInformation,                // 74
//            FileCaseSensitiveInformationForceAccessCheck,   // 75
//
//            FileMaximumInformation
//} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;


//================ FileHardLinkInformation ====================================

typedef struct _FILE_LINK_ENTRY_INFORMATION
{
    ULONG NextEntryOffset;
    LONGLONG ParentFileId;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_ENTRY_INFORMATION, * PFILE_LINK_ENTRY_INFORMATION;

typedef struct _FILE_LINKS_INFORMATION
{
    ULONG BytesNeeded;
    ULONG EntriesReturned;
    FILE_LINK_ENTRY_INFORMATION Entry;
} FILE_LINKS_INFORMATION, * PFILE_LINKS_INFORMATION;


//\Windows Kits\10\Include\10.0.22621.0\um\winternl.h
typedef
NTSTATUS
(NTAPI *
NtOpenFile_Fn)(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
);


//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile
typedef
//__kernel_entry 
//NTSYSCALLAPI 
NTSTATUS (NTAPI * NtQueryInformationFile_Fn)(
    /*[in]*/  HANDLE                 FileHandle,
    /*[out]*/ PIO_STATUS_BLOCK       IoStatusBlock,
    /*[out]*/ PVOID                  FileInformation,
    /*[in]*/  ULONG                  Length,
    /*[in]*/  FILE_INFORMATION_CLASS FileInformationClass
);


//\Windows Kits\10\Include\10.0.22621.0\um\winternl.h
typedef
NTSTATUS
(NTAPI *
NtClose_Fn)(
    IN HANDLE Handle
);


//////////////////////////////////////////////////////////////////////////////////////////////////


extern NtOpenFile_Fn g_NtOpenFile;
extern NtQueryInformationFile_Fn NtQueryInformationFile;
extern NtClose_Fn g_NtClose;

void MyHandleError(LPCTSTR psz, int nErrorNumber);
LPCTSTR ErrorMessage(DWORD error);
void DisplayError(LPCTSTR lpszFunction);
void PrintError(_In_ DWORD Status);
void PrintError(LPCTSTR errDesc);
VOID ErrorExit(LPCWSTR wszErrorMessage, DWORD dwErrorCode);
void DisplayErrorBox(LPCTSTR lpszFunction);
void MyHandleError(const char * s);
void MyHandleError(LPCTSTR psz);
void LogApiErrMsg(PCSTR Api);

BOOL WINAPI SetCurrentProcessPrivilege(PCTSTR szPrivilege, BOOL fEnable);
BOOL IsWow64();
DWORD MapFile(_In_ LPCWSTR FileName, _In_opt_ PeCallBack CallBack, _In_opt_ PVOID Context);

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
);

void ByteToStr(DWORD cb, void * pv, LPSTR sz);

PCHAR WideCharToUTF8(IN LPWSTR pws);
LPWSTR UTF8ToWideChar(IN PCHAR utf8);


//////////////////////////////////////////////////////////////////////////////////////////////////
