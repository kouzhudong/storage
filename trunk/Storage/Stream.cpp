#include "pch.h"
#include "Stream.h"


#pragma warning(disable:6031)//返回值被忽略


//////////////////////////////////////////////////////////////////////////////////////////////////


void StreamTest()
/*
Using Streams
2018/05/31

The example in this topic demonstrates how to use basic NTFS file system streams.

This example creates a file, called "TestFile," with a size of 16 bytes.
However, the file also has an additional ::$DATA stream type,
named "Stream" which adds an additional 23 bytes that is not reported by the operating system.
Therefore, when you view the file size property for the file,
you see only the size of default ::$DATA stream for the file.

If you type Type TestFile at a command prompt, it displays the following output:

This is TestFile

However, if you type the words Type TestFile:Stream, it generates the following error:

"The filename, directory name, or volume label syntax is incorrect."

To view what is in TestFile:stream, use one of the following commands:

More < TestFile:Stream

More < TestFile:Stream:$DATA

The text displayed is as follows:

This is TestFile:Stream

https://docs.microsoft.com/zh-cn/windows/win32/fileio/using-streams?redirectedfrom=MSDN
*/
{
    HANDLE hFile, hStream;
    DWORD dwRet;

    hFile = CreateFile(TEXT("TestFile"), // Filename
                       GENERIC_WRITE,    // Desired access
                       FILE_SHARE_WRITE, // Share flags
                       NULL,             // Security Attributes
                       OPEN_ALWAYS,      // Creation Disposition
                       0,                // Flags and Attributes
                       NULL);           // OVERLAPPED pointer
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Cannot open TestFile\n");
        return;
    } else {
        WriteFile(hFile,              // Handle
                  "This is TestFile", // Data to be written
                  16,                 // Size of data, in bytes
                  &dwRet,             // Number of bytes written
                  NULL);             // OVERLAPPED pointer
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }

    hStream = CreateFile(TEXT("TestFile:Stream"), // Filename
                         GENERIC_WRITE,           // Desired access
                         FILE_SHARE_WRITE,        // Share flags
                         NULL,                    // Security Attributes
                         OPEN_ALWAYS,             // Creation Disposition
                         0,                       // Flags and Attributes
                         NULL);                  // OVERLAPPED pointer
    if (hStream == INVALID_HANDLE_VALUE)
        printf("Cannot open TestFile:Stream\n");
    else {
        WriteFile(hStream,                   // Handle
                  "This is TestFile:Stream", // Data to be written
                  23,                        // Size of data
                  &dwRet,                    // Number of bytes written
                  NULL);                     // OVERLAPPED pointer
        CloseHandle(hStream);
        hStream = INVALID_HANDLE_VALUE;
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int WINAPI FileStreams(HINSTANCE hinstExe, HINSTANCE hinstPrev, LPSTR pszCmdLine, int nCmdShow)
/*
Module name: FileStreams.cpp
Written by: Jeffrey Richter
Notices: Copyright (c) 1998 Jeffrey Richter
*/
{
    LPCTSTR pszFile = __TEXT("D:\\StreamTest.tst");
    LPCTSTR pszFirstStream = __TEXT("D:\\StreamTest.tst:FirstStream");
    LPCTSTR pszCopyStream = __TEXT("D:\\StreamTest.tst:CopyStream");
    LPCTSTR pszRenameStream = __TEXT("D:\\StreamTest.tst:RenameStream");
    LPCTSTR pszMoveStream = __TEXT("D:\\StreamTest.tst:MoveStream");

    char szDataToWrite[] = "This is some data";
    char szDataToRead[100] = {0};
    HANDLE hfile;
    DWORD cb;

    // NOTE: In a real application, you do not have to open and close each stream's handle repeatedly as I've done below.

    // Create a file with no data in its unnamed stream and no named streams
    hfile = CreateFile(pszFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CloseHandle(hfile);
    // TEST: DIR (file should exist)

    // Add a named stream to the file 
    // (NOTE: Step above does NOT have to execute first)
    hfile = CreateFile(pszFirstStream, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CloseHandle(hfile);
    // TEST: MORE < C:\StreamTest.txt (nothing should be displayed)
    // TEST: MORE < C:\StreamTest.txt:FirstStream (nothing should be displayed)

    // Put some data in the named stream
    hfile = CreateFile(pszFirstStream, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    WriteFile(hfile, (PVOID)szDataToWrite, (DWORD)strlen(szDataToWrite), &cb, NULL);
    CloseHandle(hfile);
    // TEST: MORE < C:\StreamTest.txt (nothing should be displayed)
    // TEST: MORE < C:\StreamTest.txt:FirstStream (text should be displayed)

    // Get the size of the named stream
    hfile = CreateFile(pszFirstStream, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD dwSize = GetFileSize(hfile, NULL);
    CloseHandle(hfile);
    // TEST: dwSize should be the correct number of bytes

    // Read the contents of the named stream
    hfile = CreateFile(pszFirstStream, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    (void)ReadFile(hfile, (PVOID)szDataToRead, sizeof(szDataToRead), &cb, NULL);
    CloseHandle(hfile);
    // TEST: szDataToRead should contain "This is some data"

    // Make a copy of the named stream to another named stream
    CopyFile(pszFirstStream, pszCopyStream, FALSE);
    // TEST: MORE < C:\StreamTest.txt:CopyStream (text should be displayed)

    // NOTE: CopyFile doesn't always behave as expected; see below
    // 1st param	2nd param    Result
    // ----------- -----------  --------------------------------------------
    // UnnamedStrm	UnnamedStrm  Complete file copy with all streams
    // UnnamedStrm NamedStrm    UnnamedStrm copied to NamedStrm
    // NamedStrm   UnnamedStrm  File deleted; NamedStrm copied to UnnamedStrm
    // NamedStrm   NamedStrm    NamedStrm copied to NamedStrm

    // Delete all the data in a stream
    hfile = CreateFile(pszCopyStream, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
    SetEndOfFile(hfile);
    CloseHandle(hfile);
    // TEST: MORE < C:\StreamTest.txt:CopyStream (nothing displayed)

    // Delete the first named stream
    DeleteFile(pszFirstStream);
    // TEST: MORE < C:\StreamTest.txt:FirstStream (error should occur)
    // TEST: DIR (file should exist)

    // Delete the contents of the unnamed stream
    hfile = CreateFile(pszFile, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
    SetEndOfFile(hfile);
    CloseHandle(hfile);
    // TEST: MORE < C:\StreamTest.txt (nothing should display)
    // TEST: DIR (file should exist)

    // Delete the file and all of its streams
    DeleteFile(pszFile);
    // TEST: MORE < C:\StreamTest.txt (error should occur)
    // TEST: DIR (file should NOT exist)

    // Unfortunately, the Win32 function MoveFile does not support the 
    // moving/renaming of streams. This function only works on complete files.
    // There is no documented way to move/rename a stream.

    // The Win32 Backup functions can be used to enumerate the streams within a 
    // file. But they are very hard to work with and their performance is poor
    // because the function also read the stream's data.

    return(0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
文件的流的操作。

1.创建：
echo test > test.txt:test

2.查看：
more < test.txt:test

注意：
1.操作的权限，有的是要管理员的权限的。
2.请求的权限，如：读写，共享。
3.关闭句柄的作用：写/删除生效。

文件的流，不但可创建，写入，还可读取，获取属性。
*/


void TestStream()
/*
How To Use NTFS Alternate Data Streams

https://support.microsoft.com/en-us/help/105763/how-to-use-ntfs-alternate-data-streams

Summary
The documentation for the NTFS file system states that NTFS supports multiple streams of data; however,
the documentation does not address the syntax for the streams themselves.

The Windows NT Resource Kit documents the stream syntax as follows :

filename:stream
Alternate data streams are strictly a feature of the NTFS file system and
may not be supported in future file systems.
However, NTFS will be supported in future versions of Windows NT.

Future file systems will support a model based on OLE 2.0 structured storage(IStream and IStorage).
By using OLE 2.0, an application can support multiple streams on any file system and
all supported operating systems(Windows, Macintosh, Windows NT, and Win32s), not just Windows NT.
More Information
The following sample code demonstrates NTFS streams :
*/
{
    HANDLE hFile, hStream;
    DWORD dwRet;

    hFile = CreateFileA("testfile",
                        GENERIC_WRITE,
                        FILE_SHARE_WRITE,
                        NULL,
                        OPEN_ALWAYS,
                        0,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        printf("Cannot open testfile\n");
    else
        WriteFile(hFile, "This is testfile", 16, &dwRet, NULL);

    hStream = CreateFileA("testfile:stream",
                          GENERIC_WRITE,
                          FILE_SHARE_WRITE,
                          NULL,
                          OPEN_ALWAYS,
                          0,
                          NULL);
    if (hStream == INVALID_HANDLE_VALUE)
        printf("Cannot open testfile:stream\n");
    else
        WriteFile(hStream, "This is testfile:stream", 23, &dwRet, NULL);
}


/*
The file size obtained in a directory listing is 16,
because you are looking only at "testfile", and therefore
type testfile
produces the following :

This is testfile

However
type testfile : stream
produces the following :

The filename syntax is incorrect

In order to view what is in testfile : stream, use :
    more < testfile : stream
    - or -
    mep testfile : stream
    where "mep" is the Microsoft Editor available in the Platform SDK.
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
在后来的某个Windows版本中，你会发现从网上下载的文件，会带有某些标志，且运行还会收到限制，包括EXE，PPT等。

知道这是如何做到的吗？

其实是一个流，名字叫：:Zone.Identifier:$DATA。

这个标志在文件的常规属性的最下面，如果有的话。
这个属性里还有个可操作的开关，即移除它（解除锁定）。

C:\Users\Administrator>C:\Users\Administrator\Desktop\streams64.exe C:\Users\Administrator\Desktop\Streams.zip

streams v1.60 - Reveal NTFS alternate streams.
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Users\Administrator\Desktop\Streams.zip:
   :Zone.Identifier:$DATA       128
*/


/*
https://devblogs.microsoft.com/oldnewthing/?p=2753

Manipulating the zone identifier to specify where a file was download from
Raymond Chen
Raymond

November 4th, 2013

When you download a file via Internet Explorer,
the file is tagged with a little bit of information known as a zone identifier which remembers where the file was downloaded from.
This is what tells Explorer to put up the “Yo, did you really want to run this program ? ” prompt and
which is taken into account by applications so that they can do things like disable scripting and
macros when they open the document, just in case the file is malicious.

Today’s Little Program is really three Little Programs : One to read the zone identifier,
one to set the zone identifier, and one to clear it.
*/

#define STRICT


EXTERN_C
__declspec(dllexport)
int WINAPI GetFileZoneIdentifier(int argc, wchar_t ** argv)
{
    if (argc < 2)
        return 0;

    CoInitialize(0);
    CComPtr<IZoneIdentifier> spzi;

    spzi.CoCreateInstance(CLSID_PersistentZoneIdentifier);
    DWORD dwZone;//精确类型是URLZONE。
    if (SUCCEEDED(CComQIPtr<IPersistFile>(spzi)->Load(argv[1], STGM_READ)) &&
        SUCCEEDED(spzi->GetId(&dwZone))) {
        printf("Zone identifier is %d\n", dwZone); 
    } else {
        printf("Couldn't get zone identifier (perhaps there isn't one)\n");
    }

    return 0;
}


/*
The first program takes a file name on the command line(fully - qualified path, please) and
prints the zone identifier associated with it.
The numeric values for the most commonly - encountered zone identifiers are

Identifier	Value
URLZONE_LOCAL_MACHINE	0
URLZONE_INTRANET	1
URLZONE_TRUSTED	2
URLZONE_INTERNET	3
URLZONE_UNTRUSTED	4
Note also that if you want your application to be sensitive to the file zone(so that you can disable features for untrusted documents),
you should use the IInternet­Security­Manager::Map­Url­To­Zone function rather than using only the file zone identifier,
because the effective zone of a file is a combination of the file’s declared zone as well as its physical location.
(For example, a file in the Temporary Internet Files directory or
 on an untrusted server should not be given full trust regardless of what it claims.Additional reading.)

Here’s a program that uses IInternet­Security­Manager::Map­Url­To­Zone to determine the effective security zone :
*/


EXTERN_C
__declspec(dllexport)
int WINAPI MapFileZoneIdentifier(int argc, wchar_t ** argv)
{
    if (argc < 2)
        return 0;

    CoInitialize(0);
    CComPtr<IInternetSecurityManager> spism;
    spism.CoCreateInstance(CLSID_InternetSecurityManager);
    DWORD dwZone;//精确类型是URLZONE。
    if (SUCCEEDED(spism->MapUrlToZone(argv[1], &dwZone, MUTZ_ISFILE | MUTZ_DONT_UNESCAPE))) {
        printf("Zone is %d\n", dwZone);
    } else {
        printf("Couldn't get zone\n");
    }

    return 0;
}


/*
The MUTZ_IS­FILE flag saves you the hassle of having to prepend file : in front of the path,
but you still have to pass a full path because the first parameter is a URL, not a path.

Okay, that was a bit of a digression there.Let’s write another Little Program which changes the zone identifier.
*/


EXTERN_C
__declspec(dllexport)
int WINAPI SetFileZoneIdentifier(int argc, wchar_t ** argv)
{
    if (argc < 3)
        return 0;

    CoInitialize(0);
    CComPtr<IZoneIdentifier> spzi;
    spzi.CoCreateInstance(CLSID_PersistentZoneIdentifier);
    spzi->SetId(_wtol(argv[2]));
    CComQIPtr<IPersistFile>(spzi)->Save(argv[1], TRUE);
    return 0;
}


/*
This program takes two parameters : A fully - qualified path and a zone(in integer form).
It applies the zone to the file, overwriting the existing zone if any.

Finally, here’s a Little Program to remove the zone information from the file entirely.
This is the equivalent of clicking the Unblock button in the file property sheet.
*/


EXTERN_C
__declspec(dllexport)
int WINAPI RemoveFileZoneIdentifier(int argc, wchar_t ** argv)
{
    if (argc < 2)
        return 0;

    CoInitialize(0);
    CComPtr<IZoneIdentifier> spzi;
    spzi.CoCreateInstance(CLSID_PersistentZoneIdentifier);
    spzi->Remove();
    CComQIPtr<IPersistFile>(spzi)->Save(argv[1], TRUE);
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
