#include "pch.h"
#include "SparseFile.h"


#pragma warning(disable:6262)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL VolumeSupportsSparseFiles(LPCTSTR lpRootPathName)
/*!
* VolumeSupportsSparseFiles determines if the volume supports sparse streams.
*
* \param lpRootPathName
* Volume root path e.g. C:\
*/
{
    DWORD dwVolFlags;
    GetVolumeInformation(lpRootPathName, NULL, MAX_PATH, NULL, NULL, &dwVolFlags, NULL, MAX_PATH);
    return (dwVolFlags & FILE_SUPPORTS_SPARSE_FILES) ? TRUE : FALSE;
}


BOOL IsSparseFile(LPCTSTR lpFileName)
/*!
* IsSparseFile determines if a file is sparse.
*
* \param lpFileName
* File name
*/
{
    // Open the file for read
    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    // Get file information
    BY_HANDLE_FILE_INFORMATION bhfi;
    GetFileInformationByHandle(hFile, &bhfi);
    CloseHandle(hFile);

    return (bhfi.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) ? TRUE : FALSE;
}


BOOL GetSparseFileSize(LPCTSTR lpFileName)
/*!
* Get sparse file sizes.
*
* \param lpFileName
* File name
*
* \see
* http://msdn.microsoft.com/en-us/library/aa365276.aspx
*/
{
    // Retrieves the size of the specified file, in bytes. The size includes 
    // both allocated ranges and sparse ranges.
    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    LARGE_INTEGER liSparseFileSize;
    GetFileSizeEx(hFile, &liSparseFileSize);

    // Retrieves the file's actual size on disk, in bytes. The size does not 
    // include the sparse ranges.
    LARGE_INTEGER liSparseFileCompressedSize;
    liSparseFileCompressedSize.LowPart = GetCompressedFileSize(lpFileName, 
                                                               (LPDWORD)&liSparseFileCompressedSize.HighPart);

    // Print the result
    wprintf(L"\nFile total size: %I64uKB\nActual size on disk: %I64uKB\n",
            liSparseFileSize.QuadPart / 1024,
            liSparseFileCompressedSize.QuadPart / 1024);

    CloseHandle(hFile);
    return TRUE;
}


HANDLE CreateSparseFile(LPCTSTR lpFileName)
/*!
* Create a sparse file.
*
* \param lpFileName
* The name of the sparse file
*/
{
    // Create a normal file
    HANDLE hSparseFile = CreateFile(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSparseFile == INVALID_HANDLE_VALUE)
        return hSparseFile;

    // Use the DeviceIoControl function with the FSCTL_SET_SPARSE control code to mark the file as sparse. 
    // If you don't mark the file as sparse, the FSCTL_SET_ZERO_DATA control code will actually write zero bytes to the file instead of marking the region as sparse zero area.
    DWORD dwTemp;
    DeviceIoControl(hSparseFile, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &dwTemp, NULL);
    return hSparseFile;
}


void SetSparseRange(HANDLE hSparseFile, LONGLONG start, LONGLONG size)
/*!
* Converting a file region to A sparse zero area.
*
* \param hSparseFile
* Handle of the sparse file
*
* \param start
* Start address of the sparse zero area
*
* \param size
* Size of the sparse zero block. The minimum sparse size is 64KB.
*
* \remarks
* Note that SetSparseRange does not perform actual file I/O, and unlike the WriteFile function, it does not move the current file I/O pointer or sets the end-of-file pointer.
* That is, if you want to place a sparse zero block in the end of the file, you must move the file pointer accordingly using
* the FileStream.Seek function, otherwise DeviceIoControl will have no effect
*/
{
    // Specify the starting and the ending address (not the size) of the 
    // sparse zero block
    FILE_ZERO_DATA_INFORMATION fzdi;
    fzdi.FileOffset.QuadPart = start;
    fzdi.BeyondFinalZero.QuadPart = start + size;

    // Mark the range as sparse zero block
    DWORD dwTemp;
    DeviceIoControl(hSparseFile, FSCTL_SET_ZERO_DATA, &fzdi, sizeof(fzdi), NULL, 0, &dwTemp, NULL);
}


BOOL GetSparseRanges(LPCTSTR lpFileName)
/*!
* Query the sparse file layout.
*
* \param lpFileName
* File name
*/
{
    // Open the file for read
    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    LARGE_INTEGER liFileSize;
    GetFileSizeEx(hFile, &liFileSize);

    // Range to be examined (the whole file)
    FILE_ALLOCATED_RANGE_BUFFER queryRange;
    queryRange.FileOffset.QuadPart = 0;
    queryRange.Length = liFileSize;

    // Allocated areas info
    FILE_ALLOCATED_RANGE_BUFFER allocRanges[1024];

    DWORD nbytes;
    BOOL fFinished;
    _putws(L"\nAllocated ranges in the file:");
    do {
        fFinished = DeviceIoControl(hFile, 
                                    FSCTL_QUERY_ALLOCATED_RANGES,
                                    &queryRange,
                                    sizeof(queryRange),
                                    allocRanges,
                                    sizeof(allocRanges),
                                    &nbytes,
                                    NULL);
        if (!fFinished) {
            DWORD dwError = GetLastError();
            if (dwError != ERROR_MORE_DATA)// ERROR_MORE_DATA is the only error that is normal
            {
                wprintf(L"DeviceIoControl failed w/err 0x%08lx\n", dwError);
                CloseHandle(hFile);
                return FALSE;
            }
        }

        // Calculate the number of records returned
        DWORD dwAllocRangeCount = nbytes / sizeof(FILE_ALLOCATED_RANGE_BUFFER);

        // Print each allocated range
        for (DWORD i = 0; i < dwAllocRangeCount; i++) {
            wprintf(L"allocated range: [%I64u] [%I64u]\n", 
                    allocRanges[i].FileOffset.QuadPart, 
                    allocRanges[i].Length.QuadPart);
        }

        // Set starting address and size for the next query
        if (!fFinished && dwAllocRangeCount > 0) {
            queryRange.FileOffset.QuadPart = allocRanges[dwAllocRangeCount - 1].FileOffset.QuadPart +
                allocRanges[dwAllocRangeCount - 1].Length.QuadPart;
            queryRange.Length.QuadPart = liFileSize.QuadPart - queryRange.FileOffset.QuadPart;
        }
    } while (!fFinished);

    CloseHandle(hFile);
    return TRUE;
}


int CppSparseFile()
/****************************** Module Header ******************************\
* Module Name:	CppSparseFile.cpp
* Project:		CppSparseFile
* Copyright (c) Microsoft Corporation.
*
* CppSparseFile demonstrates the common operations on sparse files.
* A sparse file is a type of computer file that attempts to use file system space more efficiently when blocks allocated to the file are mostly empty.
* This is achieved by writing brief information (metadata) representing the empty blocks to disk instead of the actual "empty" space which makes up the block, using less disk space.
* You can find in this example the creation of sparse file, the detection of sparse attribute, the retrieval of sparse file size, and the query of sparse file layout.
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/opensource/licenses.mspx#Ms-PL.
* All other rights reserved.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/
{
    /////////////////////////////////////////////////////////////////////////
    // Determine if the volume support sparse streams.
    if (!VolumeSupportsSparseFiles(L"C:\\")) {
        wprintf(L"Volume %s does not support sparse streams\n", L"C:\\");
        return 1;
    }

    /////////////////////////////////////////////////////////////////////////
    // Create a sparse file.
    LPCWSTR lpFileName = L"SparseFile.tmp";
    wprintf(L"Create sparse file: %s\n", lpFileName);
    HANDLE hSparseFile = CreateSparseFile(lpFileName);
    if (hSparseFile == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFile failed w/err 0x%08lx\n", GetLastError());
        return 1;
    }

    // Write a large block of data
    const DWORD dwBlockLength = 512 * 1024; // 512KB
    BYTE * lpBlock = new BYTE[dwBlockLength];
    for (DWORD i = 0; i < dwBlockLength; i++) {
        lpBlock[i] = 0xFF;
    }
    DWORD dwBytesWritten;
    WriteFile(hSparseFile, lpBlock, dwBlockLength, &dwBytesWritten, NULL);
    delete[] lpBlock;

    // Set some sparse ranges in the block
    SetSparseRange(hSparseFile, 0, 64 * 1024 /*64KB*/);
    SetSparseRange(hSparseFile, 128 * 1024, 128 * 1024);

    // Set sparse block at the end of the file

    // 1GB sparse zeros are extended to the end of the file
    SetFilePointer(hSparseFile, 0x40000000 /*1GB*/, NULL, FILE_END);
    SetEndOfFile(hSparseFile);

    CloseHandle(hSparseFile);// Flush and close the file

    BOOL fIsSparse = IsSparseFile(lpFileName);// Determine if a file is sparse.
    wprintf(L"The file is%s sparse\n", fIsSparse ? L"" : L" not");

    GetSparseFileSize(lpFileName);// Get file size.
    GetSparseRanges(lpFileName);// Query the sparse file layout.
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


class CSparseStream
{
public:
    static BOOL DoesFileSystemSupportSparseStreams(LPCTSTR pszVolume);
    static BOOL DoesFileContainAnySparseStreams(LPCTSTR pszPathname);

    CSparseStream(HANDLE hstream) { m_hstream = hstream; m_nReadOffset = 0; }
    ~CSparseStream() { }

    operator HANDLE() const { return(m_hstream); }

public:
    BOOL IsStreamSparse() const;
    BOOL MakeSparse();
    BOOL DecommitPortionOfStream(__int64 qwFileOffsetStart, __int64 qwFileOffsetEnd);

    FILE_ALLOCATED_RANGE_BUFFER * QueryAllocatedRanges(PDWORD pdwNumEntries);
    BOOL FreeAllocatedRanges(FILE_ALLOCATED_RANGE_BUFFER * pfarb);

    BOOL  AppendQueueEntry(PVOID pvEntry, DWORD cbEntry);
    PVOID ExtractQueueEntry(PDWORD pcbEntry = NULL);
    BOOL  FreeExtractedQueueEntry(PVOID pvEntry);

private:
    HANDLE m_hstream;
    __int64 m_nReadOffset;

    static BOOL AreFlagsSet(DWORD fdwFlagBits, DWORD fFlagsToCheck) {
        return((fdwFlagBits & fFlagsToCheck) == fFlagsToCheck);
    }
};


BOOL CSparseStream::DoesFileSystemSupportSparseStreams(LPCTSTR pszVolume) {
    DWORD dwFileSystemFlags = 0;
    BOOL fOk = GetVolumeInformation(pszVolume, NULL, 0, NULL, NULL, &dwFileSystemFlags, NULL, 0);
    fOk = fOk && AreFlagsSet(dwFileSystemFlags, FILE_SUPPORTS_SPARSE_FILES);
    return(fOk);
}


BOOL CSparseStream::IsStreamSparse() const {
    BY_HANDLE_FILE_INFORMATION bhfi;
    GetFileInformationByHandle(m_hstream, &bhfi);
    return(AreFlagsSet(bhfi.dwFileAttributes, FILE_ATTRIBUTE_SPARSE_FILE));
}


BOOL CSparseStream::MakeSparse() {
    DWORD dw;
    return(DeviceIoControl(m_hstream, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &dw, NULL));
}


BOOL CSparseStream::AppendQueueEntry(PVOID pvEntry, DWORD cbEntry)
{
    SetFilePointer(m_hstream, 0, NULL, FILE_END);// Always write new entries to the end of the queue

    DWORD cb;
    BOOL fOk = WriteFile(m_hstream, &cbEntry, sizeof(cbEntry), &cb, NULL);// Write the size of the entry
    fOk = fOk && WriteFile(m_hstream, pvEntry, cbEntry, &cb, NULL);// Write the entry itself
    return(fOk);
}


PVOID CSparseStream::ExtractQueueEntry(PDWORD pcbEntry)
{
    DWORD cbEntry, cb;
    PVOID pvEntry = NULL;
    LARGE_INTEGER liOffset;
    liOffset.QuadPart = m_nReadOffset;

    // Position to the next place to read from
    SetFilePointer(m_hstream, liOffset.LowPart, &liOffset.HighPart, FILE_BEGIN);

    if (pcbEntry == NULL) pcbEntry = &cbEntry;

    BOOL fOk = ReadFile(m_hstream, pcbEntry, sizeof(*pcbEntry), &cb, NULL);// Read the size of the entry
    fOk = fOk && ((pvEntry = HeapAlloc(GetProcessHeap(), 0, *pcbEntry)) != NULL);// Allocate memory for the queue entry
    fOk = fOk && ReadFile(m_hstream, pvEntry, *pcbEntry, &cb, NULL);// Read the queue entry into the allocated memory
    if (fOk) {
        m_nReadOffset += sizeof(*pcbEntry) + *pcbEntry;
        fOk = fOk && DecommitPortionOfStream(0, m_nReadOffset);// Decommit the storage occupied the extracted queue entries
    }

    return(pvEntry);	// Return the queue entry's allocated memory
}


BOOL CSparseStream::FreeExtractedQueueEntry(PVOID pvEntry) {
    return(HeapFree(GetProcessHeap(), 0, pvEntry));// Free the queue entry's allocated memory
}


BOOL CSparseStream::DecommitPortionOfStream(__int64 qwFileOffsetStart, __int64 qwFileOffsetEnd) {
    DWORD dw;
    FILE_ZERO_DATA_INFORMATION fzdi;
    fzdi.FileOffset.QuadPart = qwFileOffsetStart;
    fzdi.BeyondFinalZero.QuadPart = qwFileOffsetEnd;
    return(DeviceIoControl(m_hstream, FSCTL_SET_ZERO_DATA, (LPVOID)&fzdi, sizeof(fzdi), NULL, 0, &dw, NULL));
}


BOOL CSparseStream::DoesFileContainAnySparseStreams(LPCTSTR pszPathname) {
    DWORD dw = GetFileAttributes(pszPathname);
    return((dw == 0xfffffff) ? FALSE : AreFlagsSet(dw, FILE_ATTRIBUTE_SPARSE_FILE));
}


FILE_ALLOCATED_RANGE_BUFFER * CSparseStream::QueryAllocatedRanges(PDWORD pdwNumEntries) {
    FILE_ALLOCATED_RANGE_BUFFER farb;
    farb.FileOffset.QuadPart = 0;
    farb.Length.LowPart = GetFileSize(m_hstream, (PDWORD)&farb.Length.HighPart);

    // There is no way to determine the correct memory block size prior to attempting to collect this data, so I just picked 1000 * sizeof(*pfarb)
    DWORD cb = 100 * sizeof(FILE_ALLOCATED_RANGE_BUFFER);
    FILE_ALLOCATED_RANGE_BUFFER * pfarb = (FILE_ALLOCATED_RANGE_BUFFER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
    BOOL fOk = DeviceIoControl(m_hstream, FSCTL_QUERY_ALLOCATED_RANGES, &farb, sizeof(farb), pfarb, cb, &cb, NULL);
    DBG_UNREFERENCED_LOCAL_VARIABLE(fOk);
    (void)GetLastError();
    *pdwNumEntries = cb / sizeof(*pfarb);
    return(pfarb);
}


BOOL CSparseStream::FreeAllocatedRanges(FILE_ALLOCATED_RANGE_BUFFER * pfarb) {
    return(HeapFree(GetProcessHeap(), 0, pfarb));// Free the queue entry's allocated memory
}


int WINAPI SparseFile()
/******************************************************************************
Module name: SparseFile.cpp
Written by: Jeffrey Richter
Notices: Copyright (c) 1998 Jeffrey Richter
******************************************************************************/
{
    TCHAR szPathName[] = __TEXT("D:\\SparseFile");

    if (!CSparseStream::DoesFileSystemSupportSparseStreams(L"D:\\")) {// run "ChkNtfs /e"
        MessageBox(NULL, L"File system doesn't support Sparse Files", NULL, MB_OK);
        return(0);
    }

    HANDLE hstream = CreateFile(szPathName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CSparseStream ss(hstream);
    BOOL f = ss.MakeSparse();
    f = ss.IsStreamSparse();

    DWORD dwNumEntries, cb;
    SetFilePointer(ss, 50 * 1024 * 1024, NULL, FILE_BEGIN);
    WriteFile(ss, "A", 1, &cb, NULL);
    cb = GetFileSize(ss, NULL);
    cb = GetCompressedFileSize(szPathName, NULL);
    FILE_ALLOCATED_RANGE_BUFFER * pfarb = ss.QueryAllocatedRanges(&dwNumEntries);
    ss.FreeAllocatedRanges(pfarb);
    ss.DecommitPortionOfStream(0, 60 * 1024 * 1024);
    pfarb = ss.QueryAllocatedRanges(&dwNumEntries);
    ss.FreeAllocatedRanges(pfarb);
    cb = GetFileSize(ss, NULL);
    cb = GetCompressedFileSize(szPathName, NULL);

    SetFilePointer(ss, 0, NULL, FILE_BEGIN);
    SetEndOfFile(ss);

    // Put a bunch of entries in the end of the queue
    BYTE bEntry[32 * 1024 - 4];	// 100KB
    for (int x = 0; x < 7; x++) ss.AppendQueueEntry(bEntry, sizeof(bEntry));
    pfarb = ss.QueryAllocatedRanges(&dwNumEntries);
    ss.FreeAllocatedRanges(pfarb);

    // Read a bunch of entries from the beginning of the queue
    for (int x = 0; x < 7; x++) {
        PVOID pvEntry = ss.ExtractQueueEntry(&cb);
        ss.FreeExtractedQueueEntry(pvEntry);
        cb = GetFileSize(ss, NULL);
        cb = GetCompressedFileSize(szPathName, NULL);
        pfarb = ss.QueryAllocatedRanges(&dwNumEntries);
        ss.FreeAllocatedRanges(pfarb);
    }
    CloseHandle(hstream);
    DeleteFile(szPathName);

    return(0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
