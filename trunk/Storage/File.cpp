#include "pch.h"
#include "File.h"


#pragma warning(disable:28183)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


void AppendingOneFileToAnotherFile()
/*
Appending One File to Another File
2018/05/31

The code example in this topic shows you how to open and close files, read and write to files, and lock and unlock files.

In the example, the application appends one file to the end of another file.
First, the application opens the file being appended with permissions that allow only the application to write to it.
However, during the append process other processes can open the file with read-only permission,
which provides a snapshot view of the file being appended.
Then, the file is locked during the actual append process to ensure the integrity of the data being written to the file.

This example does not use transactions. If you were using transacted operations, you would only be able have read-only access.
In this case, you would only see the appended data after the transaction commit operation completed.

The example also shows that the application opens two files by using CreateFile:

One.txt is opened for reading.
Two.txt is opened for writing and shared reading.
Then the application uses ReadFile and WriteFile to append the contents of One.txt to the end of Two.txt by reading and writing the 4 KB blocks.
However, before writing to the second file,
the application uses SetFilePointer to set the pointer of the second file to the end of that file,
and uses LockFile to lock the area to be written.
This prevents another thread or process with a duplicate handle from accessing the area while the write operation is in progress.
When each write operation is complete, UnlockFile is used to unlock the locked area.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/appending-one-file-to-another-file
*/
{
    HANDLE hFile;
    HANDLE hAppend;
    DWORD  dwBytesRead, dwBytesWritten, dwPos;
    BYTE   buff[4096];

    // Open the existing file.

    hFile = CreateFile(TEXT("one.txt"), // open One.txt
                       GENERIC_READ,             // open for reading
                       0,                        // do not share
                       NULL,                     // no security
                       OPEN_EXISTING,            // existing file only
                       FILE_ATTRIBUTE_NORMAL,    // normal file
                       NULL);                    // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open One.txt.");
        return;
    }

    // Open the existing file, or if the file does not exist,
    // create a new file.

    hAppend = CreateFile(TEXT("two.txt"), // open Two.txt
                         FILE_APPEND_DATA,         // open for writing
                         FILE_SHARE_READ,          // allow multiple readers
                         NULL,                     // no security
                         OPEN_ALWAYS,              // open or create
                         FILE_ATTRIBUTE_NORMAL,    // normal file
                         NULL);                    // no attr. template

    if (hAppend == INVALID_HANDLE_VALUE) {
        printf("Could not open Two.txt.");
        return;
    }

    // Append the first file to the end of the second file.
    // Lock the second file to prevent another process from
    // accessing it while writing to it. Unlock the
    // file when writing is complete.

    while (ReadFile(hFile, buff, sizeof(buff), &dwBytesRead, NULL)
           && dwBytesRead > 0) {
        dwPos = SetFilePointer(hAppend, 0, NULL, FILE_END);
        LockFile(hAppend, dwPos, 0, dwBytesRead, 0);
        WriteFile(hAppend, buff, dwBytesRead, &dwBytesWritten, NULL);
        UnlockFile(hAppend, dwPos, 0, dwBytesRead, 0);
    }

    // Close both files.

    CloseHandle(hFile);
    CloseHandle(hAppend);
}


#define BUFSIZE 1024


int TemporaryFile(int argc, TCHAR * argv[])
/*
Creating and Using a Temporary File
2018/05/31

Applications can obtain unique file and path names for temporary files by using the GetTempFileName and GetTempPath functions.
The GetTempFileName function generates a unique file name,
and the GetTempPath function retrieves the path to a directory where temporary files should be created.

The following procedure describes how an application creates a temporary file for data manipulation purposes.

To create and use a temporary file

The application opens the user-provided source text file by using CreateFile.
The application retrieves a temporary file path and file name by using the GetTempPath and GetTempFileName functions,
and then uses CreateFile to create the temporary file.
The application reads blocks of text data into a buffer,
converts the buffer contents to uppercase using the CharUpperBuffA function,
and writes the converted buffer to the temporary file.
When all of the source file is written to the temporary file, the application closes both files,
and renames the temporary file to "allcaps.txt" by using the MoveFileEx function.
Each of the previous steps is checked for success before moving to the next step, and a failure description is displayed if an error occurs.
The application will terminate immediately after displaying the error message.

Note that text file manipulation was chosen for ease of demonstration only and can be replaced with any desired data manipulation procedure required.
The data file can be of any data type, not only text.

The GetTempPath function retrieves a fully qualified path string from an environment variable but does not check in advance for the existence of the path or adequate access rights to that path, which is the responsibility of the application developer.
For more information, see GetTempPath.
In the following example, an error is regarded as a terminal condition and the application exits after sending a descriptive message to standard output.
However, many other options exist, such as prompting the user for a temporary directory or simply attempting to use the current directory.

 备注
The GetTempFileName function does not require that the GetTempPath function be used.

The following C++ example shows how to create a temporary file for data manipulation purposes.

//
//  This application opens a file specified by the user and uses
//  a temporary file to convert the file to upper case letters.
//  Note that the given source file is assumed to be an ASCII text file
//  and the new file created is overwritten each time the application is
//  run.
//

https://docs.microsoft.com/zh-cn/windows/win32/fileio/creating-and-using-a-temporary-file
*/
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hTempFile = INVALID_HANDLE_VALUE;

    BOOL fSuccess = FALSE;
    DWORD dwRetVal = 0;
    UINT uRetVal = 0;

    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    TCHAR szTempFileName[MAX_PATH];
    TCHAR lpTempPathBuffer[MAX_PATH];
    char  chBuffer[BUFSIZE];

    //LPCTSTR errMsg;

    if (argc != 2) {
        _tprintf(TEXT("Usage: %s <file>\n"), argv[0]);
        return -1;
    }

    //  Opens the existing file. 
    hFile = CreateFile(argv[1],               // file name 
                       GENERIC_READ,          // open for reading 
                       0,                     // do not share 
                       NULL,                  // default security 
                       OPEN_EXISTING,         // existing file only 
                       FILE_ATTRIBUTE_NORMAL, // normal file 
                       NULL);                 // no template 
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError(TEXT("First CreateFile failed"));
        return (1);
    }

    //  Gets the temp path env string (no guarantee it's a valid path).
    dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
                           lpTempPathBuffer); // buffer for path 
    if (dwRetVal > MAX_PATH || (dwRetVal == 0)) {
        PrintError(TEXT("GetTempPath failed"));
        if (!CloseHandle(hFile)) {
            PrintError(TEXT("CloseHandle(hFile) failed"));
            return (7);
        }
        return (2);
    }

    //  Generates a temporary file name. 
    uRetVal = GetTempFileName(lpTempPathBuffer, // directory for tmp files
                              TEXT("DEMO"),     // temp file name prefix 
                              0,                // create unique name 
                              szTempFileName);  // buffer for name 
    if (uRetVal == 0) {
        PrintError(TEXT("GetTempFileName failed"));
        if (!CloseHandle(hFile)) {
            PrintError(TEXT("CloseHandle(hFile) failed"));
            return (7);
        }
        return (3);
    }

    //  Creates the new file to write to for the upper-case version.
    hTempFile = CreateFile((LPTSTR)szTempFileName, // file name 
                           GENERIC_WRITE,        // open for write 
                           0,                    // do not share 
                           NULL,                 // default security 
                           CREATE_ALWAYS,        // overwrite existing
                           FILE_ATTRIBUTE_NORMAL,// normal file 
                           NULL);                // no template 
    if (hTempFile == INVALID_HANDLE_VALUE) {
        PrintError(TEXT("Second CreateFile failed"));
        if (!CloseHandle(hFile)) {
            PrintError(TEXT("CloseHandle(hFile) failed"));
            return (7);
        }
        return (4);
    }

    //  Reads BUFSIZE blocks to the buffer and converts all characters in 
    //  the buffer to upper case, then writes the buffer to the temporary 
    //  file. 
    do {
        if (ReadFile(hFile, chBuffer, BUFSIZE, &dwBytesRead, NULL)) {
            //  Replaces lower case letters with upper case
            //  in place (using the same buffer). The return
            //  value is the number of replacements performed,
            //  which we aren't interested in for this demo.
            CharUpperBuffA(chBuffer, dwBytesRead);

            fSuccess = WriteFile(hTempFile,
                                 chBuffer,
                                 dwBytesRead,
                                 &dwBytesWritten,
                                 NULL);
            if (!fSuccess) {
                PrintError(TEXT("WriteFile failed"));
                return (5);
            }
        } else {
            PrintError(TEXT("ReadFile failed"));
            return (6);
        }
        //  Continues until the whole file is processed.
    } while (dwBytesRead == BUFSIZE);

    //  The handles to the files are no longer needed, so
    //  they are closed prior to moving the new file.
    if (!CloseHandle(hFile)) {
        PrintError(TEXT("CloseHandle(hFile) failed"));
        return (7);
    }

    if (!CloseHandle(hTempFile)) {
        PrintError(TEXT("CloseHandle(hTempFile) failed"));
        return (8);
    }

    //  Moves the temporary file to the new text file, allowing for differnt
    //  drive letters or volume names.
    fSuccess = MoveFileEx(szTempFileName,
                          TEXT("AllCaps.txt"),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
    if (!fSuccess) {
        PrintError(TEXT("MoveFileEx failed"));
        return (9);
    } else
        _tprintf(TEXT("All-caps version of %s written to AllCaps.txt\n"), argv[1]);
    return (0);
}


void __cdecl OpenFileforWriting(int argc, TCHAR * argv[])
/*
Example: Open a File for Writing
The following example uses CreateFile to create a new file and open it for writing and WriteFile to write a simple string synchronously to the file.

A subsequent call to open this file with CreateFile will fail until the handle is closed.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/opening-a-file-for-reading-or-writing
*/
{
    HANDLE hFile;
    char DataBuffer[] = "This is some test data to write to the file.";
    DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    printf("\n");
    if (argc != 2) {
        printf("Usage Error:\tIncorrect number of arguments\n\n");
        _tprintf(TEXT("%s <file_name>\n"), argv[0]);
        return;
    }

    hFile = CreateFile(argv[1],                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);                  // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        DisplayError(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: Unable to open file \"%s\" for write.\n"), argv[1]);
        return;
    }

    _tprintf(TEXT("Writing %d bytes to %s.\n"), dwBytesToWrite, argv[1]);

    bErrorFlag = WriteFile(
        hFile,           // open file handle
        DataBuffer,      // start of data to write
        dwBytesToWrite,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);            // no overlapped structure

    if (FALSE == bErrorFlag) {
        DisplayError(TEXT("WriteFile"));
        printf("Terminal failure: Unable to write to file.\n");
    } else {
        if (dwBytesWritten != dwBytesToWrite) {
            // This is an error because a synchronous write that results in
            // success (WriteFile returns TRUE) should write all data as
            // requested. This would not necessarily be the case for
            // asynchronous writes.
            printf("Error: dwBytesWritten != dwBytesToWrite\n");
        } else {
            _tprintf(TEXT("Wrote %d bytes to %s successfully.\n"), dwBytesWritten, argv[1]);
        }
    }

    CloseHandle(hFile);
}



#define BUFFERSIZE 5
DWORD g_BytesTransferred = 0;

void DisplayError(LPTSTR lpszFunction);

VOID CALLBACK FileIOCompletionRoutine(
    __in  DWORD dwErrorCode,
    __in  DWORD dwNumberOfBytesTransfered,
    __in  LPOVERLAPPED lpOverlapped
);

VOID CALLBACK FileIOCompletionRoutine(
    __in  DWORD dwErrorCode,
    __in  DWORD dwNumberOfBytesTransfered,
    __in  LPOVERLAPPED lpOverlapped)
{
    _tprintf(TEXT("Error code:\t%x\n"), dwErrorCode);
    _tprintf(TEXT("Number of bytes:\t%x\n"), dwNumberOfBytesTransfered);
    g_BytesTransferred = dwNumberOfBytesTransfered;
}


void __cdecl OpenFileforReading(int argc, TCHAR * argv[])
//
// Note: this simplified sample assumes the file to read is an ANSI text file
// only for the purposes of output to the screen. CreateFile and ReadFile
// do not use parameters to differentiate between text and binary file types.
//
/*
Example: Open a File for Reading
The following example uses CreateFile to open an existing file for reading and ReadFile to read up to 80 characters synchronously from the file.

In this case, CreateFile succeeds only if the specified file already exists in the current directory.
A subsequent call to open this file with CreateFile will succeed if the call uses the same access and sharing modes.

Tip: You can use the file you created with the previous WriteFile example to test this example.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/opening-a-file-for-reading-or-writing
*/
{
    HANDLE hFile;
    DWORD  dwBytesRead = 0;
    char   ReadBuffer[BUFFERSIZE] = {0};
    OVERLAPPED ol = {0};

    printf("\n");
    if (argc != 2) {
        printf("Usage Error: Incorrect number of arguments\n\n");
        _tprintf(TEXT("Usage:\n\t%s <text_file_name>\n"), argv[0]);
        return;
    }

    hFile = CreateFile(argv[1],               // file to open
                       GENERIC_READ,          // open for reading
                       FILE_SHARE_READ,       // share for reading
                       NULL,                  // default security
                       OPEN_EXISTING,         // existing file only
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
                       NULL);                 // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        DisplayError(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file \"%s\" for read.\n"), argv[1]);
        return;
    }

    // Read one character less than the buffer size to save room for
    // the terminating NULL character. 

    if (FALSE == ReadFileEx(hFile, ReadBuffer, BUFFERSIZE - 1, &ol, FileIOCompletionRoutine)) {
        DisplayError(TEXT("ReadFile"));
        printf("Terminal failure: Unable to read from file.\n GetLastError=%08x\n", GetLastError());
        CloseHandle(hFile);
        return;
    }
    SleepEx(5000, TRUE);
    dwBytesRead = g_BytesTransferred;
    // This is the section of code that assumes the file is ANSI text. 
    // Modify this block for other data types if needed.

    if (dwBytesRead > 0 && dwBytesRead <= BUFFERSIZE - 1) {
        ReadBuffer[dwBytesRead] = '\0'; // NULL character

        _tprintf(TEXT("Data read from %s (%d bytes): \n"), argv[1], dwBytesRead);
        printf("%s\n", ReadBuffer);
    } else if (dwBytesRead == 0) {
        _tprintf(TEXT("No data read from file %s\n"), argv[1]);
    } else {
        printf("\n ** Unexpected value for dwBytesRead ** \n");
    }

    // It is always good practice to close the open file handles even though
    // the app will exit here and clean up open handles anyway.

    CloseHandle(hFile);
}


void FileAttributes(int argc, TCHAR * argv[])
/*
Retrieving and Changing File Attributes
2018/05/31

An application can retrieve the file attributes by using the GetFileAttributes or GetFileAttributesEx function.
The CreateFile and SetFileAttributes functions can set many of the attributes. However, applications cannot set all attributes.

The code example in this topic uses the CopyFile function to copy all text files (.txt) in the current directory to a new directory of read-only files.
Files in the new directory are changed to read only, if necessary.

The application creates the directory specified as a parameter by using the CreateDirectory function.
The directory must not exist already.

The application searches the current directory for all text files by using the FindFirstFile and FindNextFile functions.
Each text file is copied to the \TextRO directory. After a file is copied, the GetFileAttributes function determines whether or not a file is read only.
If the file is not read only, the application changes directories to \TextRO and converts the copied file to read only by using the SetFileAttributes function.

After all text files in the current directory are copied, the application closes the search handle by using the FindClose function.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/retrieving-and-changing-file-attributes
*/
{
    WIN32_FIND_DATA FileData;
    HANDLE          hSearch;
    DWORD           dwAttrs;
    TCHAR           szNewPath[MAX_PATH];

    BOOL            fFinished = FALSE;

    if (argc != 2) {
        _tprintf(TEXT("Usage: %s <dir>\n"), argv[0]);
        return;
    }

    // Create a new directory. 

    if (!CreateDirectory(argv[1], NULL)) {
        printf("CreateDirectory failed (%d)\n", GetLastError());
        return;
    }

    // Start searching for text files in the current directory. 

    hSearch = FindFirstFile(TEXT("*.txt"), &FileData);
    if (hSearch == INVALID_HANDLE_VALUE) {
        printf("No text files found.\n");
        return;
    }

    // Copy each .TXT file to the new directory 
    // and change it to read only, if not already. 

    while (!fFinished) {
        StringCchPrintf(szNewPath, sizeof(szNewPath) / sizeof(szNewPath[0]), TEXT("%s\\%s"), argv[1], FileData.cFileName);

        if (CopyFile(FileData.cFileName, szNewPath, FALSE)) {
            dwAttrs = GetFileAttributes(FileData.cFileName);
            if (dwAttrs == INVALID_FILE_ATTRIBUTES) return;

            if (!(dwAttrs & FILE_ATTRIBUTE_READONLY)) {
                SetFileAttributes(szNewPath,
                                  dwAttrs | FILE_ATTRIBUTE_READONLY);
            }
        } else {
            printf("Could not copy file.\n");
            return;
        }

        if (!FindNextFile(hSearch, &FileData)) {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                _tprintf(TEXT("Copied *.txt to %s\n"), argv[1]);
                fFinished = TRUE;
            } else {
                printf("Could not find next file.\n");
                return;
            }
        }
    }

    // Close the search handle. 

    FindClose(hSearch);
}


#define BUF_SIZE (61)


void GoDoSomethingElse(void)
// Routine Description:
//     Placeholder to demo when async I/O might want to do
//     other processing.
{
    printf("Inside GoDoSomethingElse()\n");
}


DWORD AsyncTestForEnd(HANDLE hEvent, HANDLE hFile)

// Routine Description:
//      Demonstrate async ReadFile operations that can catch
//      End-of-file conditions. Unless the operation completes
//      synchronously or the file size happens to be an exact
//      multiple of BUF_SIZE, this routine will eventually force
//      an EOF condition on any file.

// Parameters:
//      hEvent - pre-made manual-reset event.
//
//      hFile - pre-opened file handle, overlapped.
//
//      inBuffer - the buffer to read in the data to.
//
//      nBytesToRead - how much to read (usually the buffer size).

// Return Value:
//      Number of bytes read.
{
    char inBuffer[BUF_SIZE];
    DWORD nBytesToRead = BUF_SIZE;
    DWORD dwBytesRead = 0;
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    OVERLAPPED stOverlapped = {0};

    DWORD dwError = 0;
    LPCTSTR errMsg = NULL;

    BOOL bResult = FALSE;
    BOOL bContinue = TRUE;

    // Set up overlapped structure event. Other members are already 
    // initialized to zero.
    stOverlapped.hEvent = hEvent;

    // This is an intentionally brute-force loop to force the EOF trigger.
    // A properly designed loop for this simple file read would use the
    // GetFileSize API to regulate execution. However, the purpose here
    // is to demonstrate how to trigger the EOF error and handle it.

    while (bContinue) {
        // Default to ending the loop.
        bContinue = FALSE;

        // Attempt an asynchronous read operation.
        bResult = ReadFile(hFile,
                           inBuffer,
                           nBytesToRead,
                           &dwBytesRead,
                           &stOverlapped);

        dwError = GetLastError();

        // Check for a problem or pending operation. 
        if (!bResult) {
            switch (dwError) {

            case ERROR_HANDLE_EOF:
            {
                printf("\nReadFile returned FALSE and EOF condition, async EOF not triggered.\n");
                break;
            }
            case ERROR_IO_PENDING:
            {
                BOOL bPending = TRUE;

                // Loop until the I/O is complete, that is: the overlapped 
                // event is signaled.

                while (bPending) {
                    bPending = FALSE;

                    // Pending asynchronous I/O, do something else
                    // and re-check overlapped structure.
                    printf("\nReadFile operation is pending\n");

                    // Do something else then come back to check. 
                    GoDoSomethingElse();

                    // Check the result of the asynchronous read
                    // without waiting (forth parameter FALSE). 
                    bResult = GetOverlappedResult(hFile,
                                                  &stOverlapped,
                                                  &dwBytesRead,
                                                  FALSE);

                    if (!bResult) {
                        switch (dwError = GetLastError()) {
                        case ERROR_HANDLE_EOF:
                        {
                            // Handle an end of file
                            printf("GetOverlappedResult found EOF\n");
                            break;
                        }

                        case ERROR_IO_INCOMPLETE:
                        {
                            // Operation is still pending, allow while loop
                            // to loop again after printing a little progress.
                            printf("GetOverlappedResult I/O Incomplete\n");
                            bPending = TRUE;
                            bContinue = TRUE;
                            break;
                        }

                        default:
                        {
                            // Decode any other errors codes.
                            errMsg = ErrorMessage(dwError);
                            _tprintf(TEXT("GetOverlappedResult failed (%d): %s\n"),
                                     dwError, errMsg);
                            LocalFree((LPVOID)errMsg);
                        }
                        }
                    } else {
                        printf("ReadFile operation completed\n");

                        // Manual-reset event should be reset since it is now signaled.
                        ResetEvent(stOverlapped.hEvent);
                    }
                }
                break;
            }

            default:
            {
                // Decode any other errors codes.
                errMsg = ErrorMessage(dwError);
                printf("ReadFile GLE unhandled (%d): %ls\n", dwError, errMsg);
                LocalFree((LPVOID)errMsg);
                break;
            }
            }
        } else {
            // EOF demo did not trigger for the given file.
            // Note that system caching may cause this condition on most files
            // after the first read. CreateFile can be called using the
            // FILE_FLAG_NOBUFFERING parameter but it would require reads are
            // always aligned to the volume's sector boundary. This is beyond
            // the scope of this example. See comments in the main() function.

            printf("ReadFile completed synchronously\n");
        }

        // The following operation assumes the file is not extremely large, otherwise 
        // logic would need to be included to adequately account for very large
        // files and manipulate the OffsetHigh member of the OVERLAPPED structure.

        stOverlapped.Offset += dwBytesRead;
        if (stOverlapped.Offset < dwFileSize)
            bContinue = TRUE;
    }

    return stOverlapped.Offset;
}


void __cdecl EndOfFile(int argc, TCHAR * argv[])
// To force an EOF condition, execute this application specifying a
// zero-length file. This is because the offset (file pointer) must be
// at or beyond the end-of-file marker when ReadFile is called. For
// more information, see the comments for the AsyncTestForEnd routine.

/*
Testing for the End of a File
2018/05/31

The ReadFile function checks for the end-of-file condition (EOF) differently for synchronous and asynchronous read operations.
When a synchronous read operation gets to the end of a file,
ReadFile returns TRUE and sets the variable pointed to by the lpNumberOfBytesRead parameter to zero.
An asynchronous read operation can encounter the end of a file during the initiating call to ReadFile or during subsequent asynchronous operations if the file pointer is programmatically advanced beyond the end of the file.

The following C++ example shows how to test for the end of a file during a synchronous read operation.

  // Attempt a synchronous read operation.
  bResult = ReadFile(hFile, &inBuffer, nBytesToRead, &nBytesRead, NULL);

  // Check for eof.
  if (bResult &&  nBytesRead == 0)
   {
    // at the end of the file
   }

The test for end-of-file during an asynchronous read operation is slightly more involved than for a similar synchronous read operation.
The end-of-file indicator for asynchronous read operations is when GetOverlappedResult returns FALSE and GetLastError returns ERROR_HANDLE_EOF.

The following C++ example shows how to test for the end of file during an asynchronous read operation.

https://docs.microsoft.com/zh-cn/windows/win32/fileio/testing-for-the-end-of-a-file
*/
{
    HANDLE hEvent;
    HANDLE hFile;
    DWORD dwReturnValue;

    printf("\n");
    if (argc != 2) {
        printf("ERROR:\tIncorrect number of arguments\n\n");
        printf("%ls <file_name>\n", argv[0]);
        return;
    }

    hFile = CreateFile(argv[1],                // file to open
                       GENERIC_READ,           // open for reading
                       FILE_SHARE_READ,        // share for reading
                       NULL,                   // default security
                       OPEN_EXISTING,          // existing file only
                       FILE_FLAG_OVERLAPPED,   // overlapped operation
                       NULL);                  // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();
        LPCTSTR errMsg = ErrorMessage(dwError);
        printf("Could not open file (%d): %ls\n", dwError, errMsg);
        LocalFree((LPVOID)errMsg);
        return;
    }

    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (hEvent == NULL) {
        DWORD dwError = GetLastError();
        LPCTSTR errMsg = ErrorMessage(dwError);
        printf("Could not CreateEvent: %d %ls\n", dwError, errMsg);
        LocalFree((LPVOID)errMsg);
        return;
    }

    dwReturnValue = AsyncTestForEnd(hEvent, hFile);

    printf("\nRead complete. Bytes read: %d\n", dwReturnValue);

    CloseHandle(hFile);
    CloseHandle(hEvent);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


wchar_t FilePath[32797] = {0};
wchar_t lpPathBuffer[32767 + 1] = {0};


void CreateLongPathFile()
/*
文件路径的最大长度的实验代码

功能：创建一个超长的文件，长度至少为MAX_PATH.
结果：一般的程序和软件是打不开的，当然也无法进行其他的操作，如：复制，删除，改名等。移动没有测试。
注意：1.超长文件还有另一种可能，如网络文件，网络共享等。
      2.文件名和目录的长度是不可以超过MAX_PATH的，
        但是全路径是不可以超过65536/2 = 32768的。
      3.这个最大值是怎么算的，包括那些东西，如盘符包含不？
思考：一个目录下能容纳多少个文件/目录。
      达到极限了是不是就不能在创建了，这样是不是达到：不用驱动和HOOK等办法禁止文件/目录创建的功能。

参考资料：https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx

Maximum Path Length Limitation
In the Windows API (with some exceptions discussed in the following paragraphs), the maximum length for a path is MAX_PATH, 
which is defined as 260 characters.
A local path is structured in the following order: drive letter, colon, backslash, name components separated by backslashes, 
and a terminating null character.
For example, the maximum path on drive D is "D:\some 256-character path string<NUL>" where "<NUL>" represents the invisible terminating null character for the current system codepage.
(The characters < > are used here for visual clarity and cannot be part of a valid path string.)

Note  File I/O functions in the Windows API convert "/" to "\" as part of converting the name to an NT-style name, 
except when using the "\\?\" prefix as detailed in the following sections.
The Windows API has many functions that also have Unicode versions to permit an extended-length path for a maximum total path length of 32,767 characters.
This type of path is composed of components separated by backslashes, 
each up to the value returned in the lpMaximumComponentLength parameter of the GetVolumeInformation function (this value is commonly 255 characters).
To specify an extended-length path, use the "\\?\" prefix. For example, "\\?\D:\very long path".

Note  The maximum path of 32,767 characters is approximate, 
because the "\\?\" prefix may be expanded to a longer string by the system at run time, 
and this expansion applies to the total length.
The "\\?\" prefix can also be used with paths constructed according to the universal naming convention (UNC).
To specify such a path using UNC, use the "\\?\UNC\" prefix. 
For example, "\\?\UNC\server\share", where "server" is the name of the computer and "share" is the name of the shared folder.
These prefixes are not used as part of the path itself. 
They indicate that the path should be passed to the system with minimal modification,
which means that you cannot use forward slashes to represent path separators, 
or a period to represent the current directory, or double dots to represent the parent directory.
Because you cannot use the "\\?\" prefix with a relative path, 
relative paths are always limited to a total of MAX_PATH characters.

There is no need to perform any Unicode normalization on path and file name strings for use by the Windows file I/O API functions because the file system treats path and file names as an opaque sequence of WCHARs.
Any normalization that your application requires should be performed with this in mind, external of any calls to related Windows file I/O API functions.

When using an API to create a directory, the specified path cannot be so long that you cannot append an 8.3 file name (that is, the directory name cannot exceed MAX_PATH minus 12).

The shell and the file system have different requirements. 
It is possible to create a path with the Windows API that the shell user interface is not able to interpret properly.

made by correy
made at 2015.04.06
*/
{
    const wchar_t * head = L"\\\\?\\D:\\";    
    const wchar_t * end = L".txt";    

    //memset(lpPathBuffer, 0x0031, 32767);
    for (int x = 0; x < 250; x++)
    {
        lpPathBuffer[x] = 0x31;
    }
    lpPathBuffer[32767] = 0;

    lstrcpy(FilePath, head);
    lstrcat(FilePath, lpPathBuffer);

    if (!CreateDirectory(FilePath, NULL))
    {
        printf("Could not create new directory.\n");
        return;
    }

    lstrcat(FilePath, L"\\");
    lstrcat(FilePath, lpPathBuffer);
    lstrcat(FilePath, end);

    HANDLE hFile = CreateFile(FilePath,        // file to open
                              GENERIC_READ,          // open for reading
                              FILE_SHARE_READ,       // share for reading
                              NULL,                  // default security
                              CREATE_ALWAYS,         // existing file only
                              FILE_ATTRIBUTE_NORMAL, // normal file
                              NULL);                 // no attr. template 
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file (error %d)\n", GetLastError());
        return;
    }

    //下面的代码就不写了。
}


//////////////////////////////////////////////////////////////////////////////////////////////////
