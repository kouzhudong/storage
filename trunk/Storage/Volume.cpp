#include "pch.h"
#include "Volume.h"


#pragma warning(disable:6387)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////
//这段代码摘自：Windows-classic-samples\Samples\Win7Samples\winbase\io\enummount


/*
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

Copyright (C) Microsoft Corporation.  All rights reserved.

EnumMountPoints.c

This file implements a command line utility that enumerates volumes and
mount points (if any) on each volume.
*/


static void EnumMountPoints(LPTSTR szVolume);
static void PrintMountPoint(LPTSTR szVolume, LPTSTR szMountPoint);
static void PrintDosDeviceNames(LPTSTR szVolume);


void EnumVolumes()
/*
Notes
    FindFirstVolume/FindNextVolume returns the unique volume name for each.
    Since unique volume names aren't very user friendly, PrintDosDeviceNames
    prints out the Dos device name(s) that refer to the volume.
*/
{
    HANDLE hFindVolume;
    TCHAR  szVolumeName[MAX_PATH];

    // Find the first unique volume & enumerate it's mount points
    hFindVolume = FindFirstVolume(szVolumeName, MAX_PATH);

    // If we can't even find one volume, just print an error and return.
    if (hFindVolume == INVALID_HANDLE_VALUE) {
        _tprintf(_T("FindFirstVolume failed.  Error = %d\n"), GetLastError());
        return;
    }

    _tprintf(_T("\nUnique vol name: "));
    _tprintf(_T("%s\n"), szVolumeName);
    PrintDosDeviceNames(szVolumeName);
    EnumMountPoints(szVolumeName);

    // Find the rest of the unique volumes and enumerate each of their mount points.
    while (FindNextVolume(hFindVolume, szVolumeName, MAX_PATH)) {
        _tprintf(_T("\nUnique vol name: "));
        _tprintf(_T("%s\n"), szVolumeName);
        PrintDosDeviceNames(szVolumeName);
        EnumMountPoints(szVolumeName);
    }

    FindVolumeClose(hFindVolume);
}


void EnumMountPoints(LPTSTR szVolume)
/*
Parameters
    szVolume
        Unique volume name of the volume to enumerate mount points for.
Notes
    Enumerates and prints the volume mount points (if any) for the unique volume name passed in.
*/
{
    HANDLE hFindMountPoint;
    TCHAR  szMountPoint[MAX_PATH];

    // Find and print the first mount point.
    hFindMountPoint = FindFirstVolumeMountPoint(szVolume, szMountPoint, MAX_PATH);

    // If a mount point was found, print it out, if there is not even
    // one mount point, just print "None" and return.
    if (hFindMountPoint != INVALID_HANDLE_VALUE) {
        PrintMountPoint(szVolume, szMountPoint);
    } else {
        _tprintf(_T("No mount points.\n"));
        return;
    }

    // Find and print the rest of the mount points
    while (FindNextVolumeMountPoint(hFindMountPoint, szMountPoint, MAX_PATH)) {
        PrintMountPoint(szVolume, szMountPoint);
    }

    FindVolumeMountPointClose(hFindMountPoint);
}


void PrintMountPoint(LPTSTR szVolume, LPTSTR szMountPoint)
/*
Parameters
    szVolume
        Unique volume name the mount point is located on
    szMountPoint
        Name of the mount point to print
Notes
    Prints out both the mount point and the unique volume name of the volume mounted at the mount point.
*/
{
    TCHAR szMountPointPath[MAX_PATH];
    TCHAR szVolumeName[MAX_PATH];

    _tprintf(_T("  * Mount point: "));

    // Print out the mount point
    _tprintf(_T("%s\n"), szMountPoint);
    _tprintf(_T("                     ...is a mount point for...\n"));

    // Append the mount point name to the unique volume name to get the
    // complete path name for the mount point
    _tcscpy_s(szMountPointPath, MAX_PATH, szVolume);
    _tcscat_s(szMountPointPath, MAX_PATH, szMountPoint);

    // Get and print the unique volume name for the volume mounted at the mount point
    if (!GetVolumeNameForVolumeMountPoint(szMountPointPath, szVolumeName, MAX_PATH)) {
        _tprintf(_T("GetVolumeNameForVolumeMountPoint failed.  Error = %d\n"), GetLastError());
    } else {
        _tprintf(_T("                 %s\n"), szVolumeName);
    }
}


void PrintDosDeviceNames(LPTSTR szVolume)
/*
Parameters
    szVolume
        Unique volume name to get the Dos device names for
Notes
    Prints out the Dos device name(s) for the unique volume name
*/
{
    int    nStrLen;
    DWORD  dwBuffLen;
    LPTSTR szDrive;
    LPTSTR szBuffer = NULL;
    TCHAR  szVolumeName[MAX_PATH];

    // Get all logical drive strings
    dwBuffLen = GetLogicalDriveStrings(0, szBuffer);
    szBuffer = (LPTSTR)malloc(dwBuffLen * sizeof(TCHAR));
    GetLogicalDriveStrings(dwBuffLen, szBuffer);
    szDrive = szBuffer;

    _tprintf(_T("Dos drive names: "));

    nStrLen = (int)_tcslen(szDrive);

    // Get the unique volume name for each logical drive string.  If the volume
    // drive string matches the passed in volume, print out the Dos drive name
    while (nStrLen) {
        if (GetVolumeNameForVolumeMountPoint(szDrive, szVolumeName, MAX_PATH)) {
            if (_tcsicmp(szVolume, szVolumeName) == 0) {
                _tprintf(_T("%s "), szDrive);
            }
        }

        szDrive += nStrLen + 1;
        nStrLen = (int)_tcslen(szDrive);
    }

    _tprintf(_T("\n"));

    if (szBuffer)
        free(szBuffer);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void DisplayVolumePaths(__in PWCHAR VolumeName)
{
    DWORD  CharCount = MAX_PATH + 1;
    PWCHAR Names = NULL;
    PWCHAR NameIdx = NULL;
    BOOL   Success = FALSE;

    for (;;) {
        //  Allocate a buffer to hold the paths.
        Names = (PWCHAR) new BYTE[CharCount * sizeof(WCHAR)];
        if (!Names) {            
            return;//  If memory can't be allocated, return.
        }

        //  Obtain all of the paths for this volume.
        Success = GetVolumePathNamesForVolumeNameW(VolumeName, Names, CharCount, &CharCount);
        if (Success) {
            break;
        }

        if (GetLastError() != ERROR_MORE_DATA) {
            break;
        }

        //  Try again with the new suggested size.
        delete[] Names;
        Names = NULL;
    }

    if (Success) {
        //  Display the various paths.
        for (NameIdx = Names; NameIdx[0] != L'\0'; NameIdx += wcslen(NameIdx) + 1) {
            wprintf(L"  %s", NameIdx);
        }
        wprintf(L"\n");
    }

    if (Names != NULL) {
        delete[] Names;
        Names = NULL;
    }
}


void __cdecl DisplayingVolumePaths(void)
/*
Displaying Volume Paths
2018/05/31

The following C++ example shows how to display all paths for each volume and device.
For each volume in the system, the example locates the volume, obtains the device name,
obtains all paths for that volume, and displays the paths.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/displaying-volume-paths
*/
{
    DWORD  CharCount = 0;
    WCHAR  DeviceName[MAX_PATH] = L"";
    DWORD  Error = ERROR_SUCCESS;
    HANDLE FindHandle = INVALID_HANDLE_VALUE;
    BOOL   Found = FALSE;
    size_t Index = 0;
    BOOL   Success = FALSE;
    WCHAR  VolumeName[MAX_PATH] = L"";

    //  Enumerate all volumes in the system.
    FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));
    if (FindHandle == INVALID_HANDLE_VALUE) {
        Error = GetLastError();
        wprintf(L"FindFirstVolumeW failed with error code %d\n", Error);
        return;
    }

    for (;;) {
        //  Skip the \\?\ prefix and remove the trailing backslash.
        Index = wcslen(VolumeName) - 1;

        if (VolumeName[0] != L'\\' ||
            VolumeName[1] != L'\\' ||
            VolumeName[2] != L'?' ||
            VolumeName[3] != L'\\' ||
            VolumeName[Index] != L'\\') {
            Error = ERROR_BAD_PATHNAME;
            wprintf(L"FindFirstVolumeW/FindNextVolumeW returned a bad path: %s\n", VolumeName);
            break;
        }

        //  QueryDosDeviceW does not allow a trailing backslash, so temporarily remove it.
        VolumeName[Index] = L'\0';
        CharCount = QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName));
        VolumeName[Index] = L'\\';
        if (CharCount == 0) {
            Error = GetLastError();
            wprintf(L"QueryDosDeviceW failed with error code %d\n", Error);
            break;
        }

        wprintf(L"\nFound a device:\n %s", DeviceName);
        wprintf(L"\nVolume name: %s", VolumeName);
        wprintf(L"\nPaths:");
        DisplayVolumePaths(VolumeName);

        //  Move on to the next volume.
        Success = FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName));
        if (!Success) {
            Error = GetLastError();
            if (Error != ERROR_NO_MORE_FILES) {
                wprintf(L"FindNextVolumeW failed with error code %d\n", Error);
                break;
            }

            //  Finished iterating
            //  through all the volumes.
            Error = ERROR_SUCCESS;
            break;
        }
    }

    FindVolumeClose(FindHandle);
    FindHandle = INVALID_HANDLE_VALUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
DLEDIT  -- Drive Letter Assignment Editor

Command-line syntax:
   DLEDIT <drive letter> <device name>      -- Adds a drive letter
   DLEDIT -r <drive letter>                 -- Removes a drive letter

Command-line examples:

   If E: refers to the CD-ROM drive, use the following commands to
   make F: point to the CD-ROM drive instead.

   DLEDIT -r E:\
   DLEDIT F:\ \Device\CdRom0

*****************************************************************
WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING

   This program will change drive letter assignments, and the
   changes persist through reboots. Do not remove drive letters
   of your hard disks if you do not have this program on floppy
   disk or you might not be able to access your hard disks again!
*****************************************************************
*/

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif

#ifdef NTDDI_VERSION
#undef NTDDI_VERSION
#define NTDDI_VERSION 0x05000000
#endif

#if defined (DEBUG)
static void DebugPrint(LPCTSTR pszMsg, DWORD dwErr);
#define DEBUG_PRINT(pszMsg, dwErr) DebugPrint(pszMsg, dwErr)
#else
#define DEBUG_PRINT(pszMsg, dwErr) NULL
#endif

#pragma warning (disable : 4800)

void PrintHelp(LPCTSTR pszAppName);


void EditingDriveLetterAssignments(int argc, TCHAR * argv[])
/*
The main function is the main routine. It parses the command-line
arguments and either removes or adds a drive letter.

Parameters
   argc
      Count of the command-line arguments
   argv
      Array of pointers to the individual command-line arguments

Editing Drive Letter Assignments
2018/05/31

The code example in this topic shows you how to add or remove persistent drive letter assignments.
These drive letter assignments persist through system shutdown.
For more information, see Assigning a Drive Letter to a Volume.

The code example uses the following functions:
DefineDosDevice, DeleteVolumeMountPoint, GetVolumeNameForVolumeMountPoint, and SetVolumeMountPoint.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/editing-drive-letter-assignments
*/
{
    TCHAR * pszDriveLetter, * pszNTDevice, * pszOptions;
    TCHAR szUniqueVolumeName[MAX_PATH];
    TCHAR szDriveLetterAndSlash[4];
    TCHAR szDriveLetter[3];
    BOOL  fRemoveDriveLetter;
    BOOL  fResult;

    if (argc != 3) {
        PrintHelp(argv[0]);
        return;
    }

    // Use the command line to see if user wants to add or remove the 
    // drive letter. Do this by looking for the -r option.
    fRemoveDriveLetter = !lstrcmpi(argv[1], TEXT("-r"));
    if (fRemoveDriveLetter) {
        // User wants to remove the drive letter. Command line should 
        // be: dl -r <drive letter>

        pszOptions = argv[1];
        pszDriveLetter = argv[2];
        pszNTDevice = NULL;
    } else {
        // User wants to add a drive letter. Command line should be:
        // dl <drive letter> <NT device name>

        pszOptions = NULL;
        pszDriveLetter = argv[1];
        pszNTDevice = argv[2];
    }

    // GetVolumeNameForVolumeMountPoint, SetVolumeMountPoint,
    // and DeleteVolumeMountPoint require drive letters to have a trailing backslash. 
    // However, DefineDosDevice requires that the trailing backslash be absent. So, use:
    // 
    //    szDriveLetterAndSlash     for the mounted folder functions
    //    szDriveLetter             for DefineDosDevice
    // 
    // This way, command lines that use a: or a:\ 
    // for drive letters can be accepted without writing back to the original command-line argument.

    szDriveLetter[0] = pszDriveLetter[0];
    szDriveLetter[1] = TEXT(':');
    szDriveLetter[2] = TEXT('\0');

    szDriveLetterAndSlash[0] = pszDriveLetter[0];
    szDriveLetterAndSlash[1] = TEXT(':');
    szDriveLetterAndSlash[2] = TEXT('\\');
    szDriveLetterAndSlash[3] = TEXT('\0');

    // Now add or remove the drive letter.
    if (fRemoveDriveLetter) {
        fResult = DeleteVolumeMountPoint(szDriveLetterAndSlash);
        if (!fResult)
            _tprintf(TEXT("error %lu: couldn't remove %s\n"), GetLastError(), szDriveLetterAndSlash);
    } else {
        // To add a drive letter that persists through reboots, use SetVolumeMountPoint.
        // This requires the volume GUID path of the device to which the new drive letter will refer. 
        // To get the volume GUID path, use GetVolumeNameForVolumeMountPoint; 
        // it requires the drive letter to already exist. So, first define the drive 
        // letter as a symbolic link to the device name. After  
        // you have the volume GUID path the new drive letter will 
        // point to, you must delete the symbolic link because the 
        // mount manager allows only one reference to a device at a time (the new one to be added).

        fResult = DefineDosDevice(DDD_RAW_TARGET_PATH, szDriveLetter, pszNTDevice);
        if (fResult) {
            // If GetVolumeNameForVolumeMountPoint fails, then SetVolumeMountPoint will also fail. 
            // However, DefineDosDevice must be called to remove the temporary symbolic link. 
            // Therefore, set szUniqueVolume to a known empty string.

            if (!GetVolumeNameForVolumeMountPoint(szDriveLetterAndSlash, szUniqueVolumeName, MAX_PATH)) {
                DEBUG_PRINT(TEXT("GetVolumeNameForVolumeMountPoint failed"), GetLastError());
                szUniqueVolumeName[0] = '\0';
            }

            fResult = DefineDosDevice(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, szDriveLetter, pszNTDevice);
            if (!fResult)
                DEBUG_PRINT(TEXT("DefineDosDevice failed"), GetLastError());

            fResult = SetVolumeMountPoint(szDriveLetterAndSlash, szUniqueVolumeName);
            if (!fResult)
                _tprintf(TEXT("error %lu: could not add %s\n"), GetLastError(), szDriveLetterAndSlash);
        }
    }
}


void PrintHelp(LPCTSTR pszAppName)
/*
The PrintHelp function prints the command-line usage help.
Parameters
   pszAppName
      The name of the executable. Used in displaying the help.
*/
{
    _tprintf(TEXT("Adds/removes a drive letter assignment for a device.\n\n"));
    _tprintf(TEXT("Usage: %s <Drive> <Device name> add a drive letter\n"), pszAppName);
    _tprintf(TEXT("       %s -r <Drive>            remove a drive letter\n\n"), pszAppName);
    _tprintf(TEXT("Example: %s e:\\ \\Device\\CdRom0\n"), pszAppName);
    _tprintf(TEXT("         %s -r e:\\\n"), pszAppName);
}


#if defined (DEBUG)
void DebugPrint(LPCTSTR pszMsg, DWORD dwErr)
/*
The DebugPrint function prints a string to STDOUT.

Parameters
   pszMsg
      The string to be printed to STDOUT.
   dwErr
      The error code; usually obtained from GetLastError. If dwErr is
      zero, no error code is added to the error string. If dwErr is
      nonzero, the error code will be printed in the error string.
*/
{
    if (dwErr)
        _tprintf(TEXT("%s: %lu\n"), pszMsg, dwErr);
    else
        _tprintf(TEXT("%s\n"), pszMsg);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


#define BUFSIZE MAX_PATH 


int CreatingMountedFolder(int argc, TCHAR * argv[])
/*
Creating a Mounted Folder
2018/05/31

argv[1]：是个目录，必须存在，必须为空。
argv[2]：

The following sample demonstrates how to create a mounted folder.
For more information, see Creating Mounted Folders.

This sample uses the following functions: GetVolumeNameForVolumeMountPoint and SetVolumeMountPoint.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/mounting-a-volume-at-a-mount-point
*/
{
    BOOL bFlag;
    TCHAR Buf[BUFSIZE];     // temporary buffer for volume name

    if (argc != 3) {
        _tprintf(TEXT("Usage: %s <mount_point> <volume>\n"), argv[0]);
        _tprintf(TEXT("For example, \"%s c:\\mnt\\fdrive\\ f:\\\"\n"), argv[0]);
        return(-1);
    }

    // We should do some error checking on the inputs. 
    // Make sure there are colons and backslashes in the right places, and so on 
    bFlag = GetVolumeNameForVolumeMountPoint(
        argv[2], // input volume mount point or directory
        Buf, // output volume name buffer
        BUFSIZE  // size of volume name buffer
    );
    if (bFlag != TRUE) {
        _tprintf(TEXT("Retrieving volume name for %s failed.\n"), argv[2]);
        return (-2);
    }

    _tprintf(TEXT("Volume name of %s is %s\n"), argv[2], Buf);
    bFlag = SetVolumeMountPoint(
        argv[1], // mount point
        Buf  // volume to be mounted
    );
    if (!bFlag)
        _tprintf(TEXT("Attempt to mount %s at %s failed.\n"), argv[2], argv[1]);

    return (bFlag);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void EnumeratingVolumeGUIDPaths(void)
/*
Enumerating Volume GUID Paths
2018/05/31

The code example in this topic shows you how to obtain a volume GUID path for each local volume associated with a drive letter that is currently in use on the computer.

The code example uses the GetVolumeNameForVolumeMountPoint function.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/enumerating-unique-volume-names
*/
{
    BOOL bFlag;
    TCHAR Buf[BUFSIZE];           // temporary buffer for volume name
    TCHAR Drive[] = TEXT("c:\\"); // template drive specifier
    TCHAR I;                      // generic loop counter

    // Walk through legal drive letters, skipping floppies.
    for (I = TEXT('c'); I < TEXT('z'); I++) {
        // Stamp the drive for the appropriate letter.
        Drive[0] = I;
        bFlag = GetVolumeNameForVolumeMountPoint(
            Drive,     // input volume mount point or directory
            Buf,       // output volume name buffer
            BUFSIZE); // size of volume name buffer
        if (bFlag) {
            _tprintf(TEXT("The ID of drive \"%s\" is \"%s\"\n"), Drive, Buf);
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void Syntax(TCHAR * argv)
{
    _tprintf(TEXT("%s unmounts a volume from a volume mount point\n"), argv);
    _tprintf(TEXT("For example: \"%s c:\\mnt\\fdrive\\\"\n"), argv);
}


int DeletingMountedFolder(int argc, TCHAR * argv[])
/*
Deleting a Mounted Folder
2018/05/31

The code example in this topic shows you how to delete a mounted folder by using the DeleteVolumeMountPoint function.
For more information, see Creating Mounted Folders.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/unmounting-a-volume-at-a-mount-point
*/
{
    BOOL bFlag;

    if (argc != 2) {
        Syntax(argv[0]);
        return (-1);
    }

    // We should do some error checking on the path argument, such as
    // ensuring that there is a trailing backslash.

    bFlag = DeleteVolumeMountPoint(
        argv[1] // Path of the volume mount point
    );

    _tprintf(TEXT("\n%s %s in unmounting the volume at %s\n"), argv[0],
             bFlag ? TEXT("succeeded") : TEXT("failed"), argv[1]);

    return (bFlag);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _FILE_SYSTEM_RECOGNITION_STRUCTURE {
    UCHAR  Jmp[3];
    UCHAR  FsName[8];
    UCHAR  MustBeZero[5];
    ULONG  Identifier;
    USHORT Length;
    USHORT Checksum;
} FILE_SYSTEM_RECOGNITION_STRUCTURE, * PFILE_SYSTEM_RECOGNITION_STRUCTURE;


USHORT ComputeFileSystemInformationChecksum(__in PFILE_SYSTEM_RECOGNITION_STRUCTURE Fsrs)
/*++
Routine Description:
    This routine computes the file record checksum.
Arguments:
    Fsrs - Pointer to the record.
Return Value:
    The checksum result.

Computing a File System Recognition Checksum
2018/05/31

The FILE_SYSTEM_RECOGNITION_STRUCTURE structure,
defined internally by Windows and used by file system recognition (FRS),
contains a checksum value that must be properly computed for FRS to work properly with a specified unrecognized file system.
The following example accomplishes this computation.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/computing-a-file-system-recognition-checksum
--*/
{
    USHORT Checksum = 0;
    USHORT i;
    PUCHAR Buffer = (PUCHAR)Fsrs;
    USHORT StartOffset;

    //  Skip the jump instruction
    StartOffset = FIELD_OFFSET(FILE_SYSTEM_RECOGNITION_STRUCTURE, FsName);

    for (i = StartOffset; i < Fsrs->Length; i++) {
        //  Skip the checksum field itself, which is a USHORT.
        if ((i == FIELD_OFFSET(FILE_SYSTEM_RECOGNITION_STRUCTURE, Checksum)) ||
            (i == FIELD_OFFSET(FILE_SYSTEM_RECOGNITION_STRUCTURE, Checksum) + 1)) {
            continue;
        }

        Checksum = ((Checksum & 1) ? 0x8000 : 0) + (Checksum >> 1) + Buffer[i];
    }

    return Checksum;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


STDMETHODIMP CheckFileSystem(PCWSTR pcwszDrive)
/*
Obtaining File System Recognition Information
2018/05/31

File system recognition is the ability to recognize storage media that contain a valid file system/volume layout that has not been defined yet,
but the media is able to identify itself through the presence of the recognition structure defined internally by Windows.

Because no existing file system will recognize a new disk layout,
the "RAW" file system will mount the volume and provide direct block level access.
The "RAW" file system, incorporated in NtosKrnl,
will have the ability to read the file system recognition structure and
provide applications access to such structures through the file system control request FSCTL_QUERY_FILE_SYSTEM_RECOGNITION,
shown in the following example.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/obtaining-file-system-recognition-information
*/
{
    HRESULT hr = S_OK;
    HANDLE  hDisk = INVALID_HANDLE_VALUE;
    BOOL    fResult = FALSE;
    ULONG   BytesReturned = 0;
    FILE_SYSTEM_RECOGNITION_INFORMATION     FsRi = {0};

    // Open the target, for example "\\.\C:"
    wprintf(L"CreateFile on %s...", pcwszDrive);
    hDisk = CreateFile(pcwszDrive,
                       FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_TRAVERSE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        wprintf(L"CreateFile failed on %s, GLE = 0x%x\n", pcwszDrive, GetLastError());
        goto exit;
    }
    wprintf(L"succeeded.\n\n");

    wprintf(L"\nPress Any Key to send down the FSCTL\n");
    (void)_getwch();

    // Send down the FSCTL
    wprintf(L"Calling DeviceIoControl( FSCTL_QUERY_FILE_SYSTEM_RECOGNITION ) ");

    fResult = DeviceIoControl(hDisk,
                              FSCTL_QUERY_FILE_SYSTEM_RECOGNITION,
                              NULL,
                              0,
                              &FsRi,
                              sizeof(FsRi),
                              &BytesReturned,
                              NULL);
    if (!fResult) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        wprintf(L"failed GLE = 0x%x\n", GetLastError());
        goto exit;
    }

    wprintf(L"succeeded.\n\n");
    wprintf(L"FSCTL_QUERY_FILE_SYSTEM_RECOGNITION returned success.\n");
    wprintf(L"FSCTL_QUERY_FILE_SYSTEM_RECOGNITION retrieved \"%S\".\n", FsRi.FileSystem);

exit:

    if (hDisk != INVALID_HANDLE_VALUE) {
        CloseHandle(hDisk);
        hDisk = INVALID_HANDLE_VALUE;
    }

    return hr;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#define BUF_LEN 4096


void ChangeJournalRecords()
/*
Walking a Buffer of Change Journal Records

2018/05/31

The control codes that return update sequence number (USN) change journal records,
FSCTL_READ_USN_JOURNAL and FSCTL_ENUM_USN_DATA, return similar data in the output buffer.
Both return a USN followed by zero or more change journal records, each in a USN_RECORD_V2 or USN_RECORD_V3 structure.

The target volume for USN operations must be ReFS or NTFS 3.0 or later.
To obtain the NTFS version of a volume, open a command prompt with Administrator access rights and execute the following command:

FSUtil.exe FSInfo NTFSInfo X**:**

where X is the drive letter of the volume.

The following list identifies ways to get change journal records:

Use FSCTL_ENUM_USN_DATA to get a listing (enumeration) of all change journal records between two USNs.
Use FSCTL_READ_USN_JOURNAL to be more selective, such as selecting specific reasons for changes or returning when a file is closed.

Both of these operations return only the subset of change journal records that meet the specified criteria.

The USN returned as the first item in the output buffer is the USN of the next record number to be retrieved.
Use this value to continue reading records from the end boundary forward.

The FileName member of USN_RECORD_V2 or USN_RECORD_V3 contains the name of the file to which the record in question applies.
The file name varies in length, so USN_RECORD_V2 and USN_RECORD_V3 are variable length structures.
Their first member, RecordLength, is the length of the structure (including the file name), in bytes.

When you work with the FileName member of USN_RECORD_V2 and USN_RECORD_V3 structures,
do not assume that the file name contains a trailing '\0' delimiter.
To determine the length of the file name, use the FileNameLength member.

The following example calls FSCTL_READ_USN_JOURNAL and walks the buffer of change journal records that the operation returns.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/walking-a-buffer-of-change-journal-records
*/
{
    HANDLE hVol;
    CHAR Buffer[BUF_LEN];
    USN_JOURNAL_DATA JournalData;
    READ_USN_JOURNAL_DATA ReadData = {0, 0xFFFFFFFF, FALSE, 0, 0};
    PUSN_RECORD UsnRecord;
    DWORD dwBytes;
    DWORD dwRetBytes;
    int I;

    hVol = CreateFile(TEXT("\\\\.\\c:"),
                      GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL,
                      OPEN_EXISTING,
                      0,
                      NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed (%d)\n", GetLastError());
        return;
    }

    if (!DeviceIoControl(hVol,
                         FSCTL_QUERY_USN_JOURNAL,
                         NULL,
                         0,
                         &JournalData,
                         sizeof(JournalData),
                         &dwBytes,
                         NULL)) {
        printf("Query journal failed (%d)\n", GetLastError());
        return;
    }

    ReadData.UsnJournalID = JournalData.UsnJournalID;

    printf("Journal ID: %I64x\n", JournalData.UsnJournalID);
    printf("FirstUsn: %I64x\n\n", JournalData.FirstUsn);

    for (I = 0; I <= 10; I++) {
        memset(Buffer, 0, BUF_LEN);
        if (!DeviceIoControl(hVol,
                             FSCTL_READ_USN_JOURNAL,
                             &ReadData,
                             sizeof(ReadData),
                             &Buffer,
                             BUF_LEN,
                             &dwBytes,
                             NULL)) {
            printf("Read journal failed (%d)\n", GetLastError());
            return;
        }

        dwRetBytes = dwBytes - sizeof(USN);

        // Find the first record
        UsnRecord = (PUSN_RECORD)(((PUCHAR)Buffer) + sizeof(USN));

        printf("****************************************\n");

        // This loop could go on for a long time, given the current buffer size.
        while (dwRetBytes > 0) {
            printf("USN: %I64x\n", UsnRecord->Usn);
            printf("File name: %.*S\n", UsnRecord->FileNameLength / 2, UsnRecord->FileName);
            printf("Reason: %x\n", UsnRecord->Reason);
            printf("\n");

            dwRetBytes -= UsnRecord->RecordLength;

            // Find the next record
            UsnRecord = (PUSN_RECORD)(((PCHAR)UsnRecord) + UsnRecord->RecordLength);
        }
        
        ReadData.StartUsn = *(USN *)&Buffer;// Update starting USN for next call
    }

    CloseHandle(hVol);
}


void ChangeJournalRecords2()
/*
ntfs的冰山一角：Change Journal Records，更多的功能有待发掘和理解。
本文稍微修改自：http://msdn.microsoft.com/en-us/library/aa365736%28v=VS.85%29.aspx
*/
{
    HANDLE hVol = CreateFile(TEXT("\\\\.\\c:"),
                             GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL,
                             OPEN_EXISTING,
                             0,
                             NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        return;
    }

    //获取JournalData结构及dwBytes个数。
    DWORD dwBytes;
    USN_JOURNAL_DATA JournalData;
    if (!DeviceIoControl(hVol,
                         FSCTL_QUERY_USN_JOURNAL,
                         NULL,
                         0,
                         &JournalData,
                         sizeof(JournalData),
                         &dwBytes,
                         NULL)) {
        return;
    }

    READ_USN_JOURNAL_DATA ReadData = {0, 0xFFFFFFFF, FALSE, 0, 0};
    ReadData.UsnJournalID = JournalData.UsnJournalID;

    printf("Journal ID: %I64x\n", JournalData.UsnJournalID);
    printf("FirstUsn: %I64x\n\n", JournalData.FirstUsn);

    for (int I = 0; I <= 10; I++) {
        CHAR Buffer[4096] = {0};

        //dwBytes有返回值。
        if (!DeviceIoControl(hVol,
                             FSCTL_READ_USN_JOURNAL,
                             &ReadData,
                             sizeof(ReadData),
                             &Buffer,
                             sizeof(Buffer),
                             &dwBytes,
                             NULL)) {
            return;
        }

        DWORD dwRetBytes = dwBytes - sizeof(USN);
        PUSN_RECORD UsnRecord = (PUSN_RECORD)(((PUCHAR)Buffer) + sizeof(USN)); // Find the first record 

        printf("****************************************\n");

        while (dwRetBytes > 0)// This loop could go on for a long time, given the current buffer size.
        {
            printf("USN: %I64x\n", UsnRecord->Usn);
            printf("File name: %.*S\n", UsnRecord->FileNameLength / 2, UsnRecord->FileName);
            printf("Reason: %x\n", UsnRecord->Reason);
            printf("\n");

            dwRetBytes -= UsnRecord->RecordLength;
            UsnRecord = (PUSN_RECORD)(((PCHAR)UsnRecord) + UsnRecord->RecordLength); // Find the next record
        }

        ReadData.StartUsn = *(USN *)&Buffer; // Update starting USN for next call
    }

    CloseHandle(hVol);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL CheckDiskResourceAndGetDetails(HRESOURCE hResource, LPWSTR szGUID, LPWSTR szPath)
/// <summary>
/// Checks if the resource is a valid cluster disk resource and returns its GUID and Path via out parameters. 
/// </summary>
/// <param name="hResource">Handle for a cluster resource</param>
/// <returns>TRUE if the GUID and Path is retrieved successfully else returns FALSE</returns>
{
    BOOL bIsDisk = FALSE;
    CLUSPROP_VALUE * cv = NULL;
    BYTE * lpbBuffer = NULL;
    DWORD dwRetVal;
    DWORD dwBytes = 0;

    dwRetVal = ClusterResourceControl(
        hResource,
        NULL,
        CLUSCTL_RESOURCE_STORAGE_GET_DISK_INFO_EX,
        NULL,
        0,
        lpbBuffer,
        0,
        &dwBytes);
    if (ERROR_MORE_DATA == dwRetVal || ERROR_SUCCESS == dwRetVal) {
        if (lpbBuffer)
            delete[] lpbBuffer;

        lpbBuffer = new BYTE[dwBytes];
        if (NULL == lpbBuffer) {
            wprintf(L"Error: could not allocate memory.\n");
            return FALSE;
        }

        dwRetVal = ClusterResourceControl(
            hResource,
            NULL,
            CLUSCTL_RESOURCE_STORAGE_GET_DISK_INFO_EX,
            NULL,
            0,
            lpbBuffer,
            dwBytes,
            &dwBytes);
        if (ERROR_SUCCESS != dwRetVal && ERROR_INVALID_FUNCTION != dwRetVal) {
            if (ERROR_MORE_DATA == dwRetVal) {
                wprintf(L"Error: more data needed.\n");
            } else {
                wprintf(L"ClusterResourceControl failed: %d\n", dwRetVal);
            }
        } else {
            cv = (CLUSPROP_VALUE *)lpbBuffer;

            while ((NULL != cv) && (CLUSPROP_TYPE_PARTITION_INFO_EX != cv->Syntax.wType)) {
                cv = (CLUSPROP_VALUE *)(((BYTE *)&(cv->cbLength)) + cv->cbLength + sizeof(DWORD));
                if (cv >= (CLUSPROP_VALUE *)&lpbBuffer[dwBytes]) {
                    cv = NULL;
                }
            }

            if (NULL != cv) {
                bIsDisk = TRUE;
                GUID guid = ((CLUSPROP_PARTITION_INFO_EX *)cv)->VolumeGuid;
                (void)StringFromGUID2(guid, szGUID, MAX_PATH);
                wsprintf(szGUID, L"%s", szGUID);
                wsprintf(szPath, L"%s", ((CLUSPROP_PARTITION_INFO_EX *)cv)->szDeviceName);
            }
        } // else error_success

        delete[] lpbBuffer;
    } else if (ERROR_SUCCESS != dwRetVal && ERROR_INVALID_FUNCTION != dwRetVal) {
        wprintf(L"ClusterResourceControl failed: %d\n", dwRetVal);
    }

    return bIsDisk;
}


int ClusterDiskDetails(int argc, WCHAR * argv[])
/****************************** Module Header ******************************\
* Module Name:    Main.cpp
* Project:        CppClusterDiskDetails
* Copyright (c) Microsoft Corporation
*
* Main.cpp Defines the entry point for the console application.
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/en-us/openness/licenses.aspx#MPL.
* All other rights reserved.
*
* 工程出处：Retrieving Volume GUID for a cluster volume (CppClusterDiskDetails)
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\*****************************************************************************/
{
    HCLUSTER hCluster = NULL;
    HCLUSENUM hClusEnum = NULL;
    DWORD dwSignature = 0;
    WCHAR szVolGUID[MAX_PATH];
    WCHAR szPath[MAX_PATH];
    WCHAR * lpwClusterName = NULL;

    if (argc > 1) // We have a parameter
    {
        lpwClusterName = argv[1];
        wprintf(L"Cluster: \"%s\"\n", lpwClusterName);
    }

    hCluster = OpenCluster(lpwClusterName);

    DWORD dw = GetLastError();

    if (NULL == hCluster) {
        wprintf(L"Could not open cluster\n");
    } else {
        hClusEnum = ClusterOpenEnum(hCluster, CLUSTER_ENUM_RESOURCE);
        if (NULL == hClusEnum) {
            wprintf(L"Could not open enum.\n");
        } else {
            WCHAR lpwName[MAX_PATH];
            DWORD dwCBName;
            DWORD dwType;
            DWORD dwIndex;
            DWORD dwRetVal;
            HRESOURCE hResource = NULL;

            dwIndex = 0;
            dwCBName = 100 * sizeof(WCHAR);
            dwRetVal = ClusterEnum(hClusEnum, dwIndex, &dwType, lpwName, &dwCBName);

            wprintf(L"Physical disks: \n");

            while (ERROR_SUCCESS == dwRetVal) {
                hResource = OpenClusterResource(hCluster, lpwName);
                if (NULL == hResource) {
                    wprintf(L"Error: could not open resource %s\n", lpwName);
                } else {
                    if (CheckDiskResourceAndGetDetails(hResource, szVolGUID, szPath)) {
                        wprintf(L" \"%s(%s)\" Volume GUID = %s\n", lpwName, szPath, szVolGUID);
                    }

                    CloseClusterResource(hResource);
                    hResource = NULL;
                }

                dwIndex++;
                dwCBName = 100 * sizeof(WCHAR);
                dwRetVal = ClusterEnum(hClusEnum, dwIndex, &dwType, lpwName, &dwCBName);
            } // while

            wprintf(L"\n");

            ClusterCloseEnum(hClusEnum);
            hClusEnum = NULL;
        }

        CloseCluster(hCluster);
        hCluster = NULL;
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
