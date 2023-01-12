/*
File System Redirector
2018/05/31

The %windir%\System32 directory is reserved for 64-bit applications on 64-bit Windows.
Most DLL file names were not changed when 64-bit versions of the DLLs were created, 
so 32-bit versions of the DLLs are stored in a different directory. 
WOW64 hides this difference by using a file system redirector.

In most cases, whenever a 32-bit application attempts to access %windir%\System32, %windir%\lastgood\system32,
or %windir%\regedit.exe, the access is redirected to an architecture-specific path.

 ��ע
These paths are provided for reference only. 
For compatibility, applications should not use these paths directly. Instead, they should call the APIs described below.

�� 1
Original Path	Redirected Path for 32-bit x86 Processes	Redirected Path for 32-bit ARM Processes
%windir%\System32	%windir%\SysWOW64	%windir%\SysArm32
%windir%\lastgood\system32	%windir%\lastgood\SysWOW64	%windir%\lastgood\SysArm32
%windir%\regedit.exe	%windir%\SysWOW64\regedit.exe	%windir%\ SysArm32\regedit.exe


If the access causes the system to display the UAC prompt, redirection does not occur.
Instead, the 64-bit version of the requested file is launched. 
To prevent this problem, either specify the SysWOW64 directory to avoid redirection and ensure access to the 32-bit version of the file, 
or run the 32-bit application with administrator privileges so the UAC prompt is not displayed.

**Windows Server 2003 and Windows XP:  ** UAC is not supported.

Certain subdirectories are exempt from redirection. Access to these subdirectories is not redirected to %windir%\SysWOW64:

%windir%\system32\catroot
%windir%\system32\catroot2
%windir%\system32\driverstore
%windir%\system32\drivers\etc
%windir%\system32\logfiles
%windir%\system32\spool
**Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  **%windir%\system32\driverstore is redirected.

To retrieve the name of the 32-bit system directory, 
64-bit applications should use the GetSystemWow64Directory2 function (Windows 10, version 1511) or the GetSystemWow64Directory function.

Applications should use the SHGetKnownFolderPath function to determine the %ProgramFiles% directory name.

Windows Server 2003 and Windows XP: Applications should use the SHGetSpecialFolderPath function to determine the %ProgramFiles% directory name.

Applications can control the WOW64 file system redirector using the Wow64DisableWow64FsRedirection, 
Wow64EnableWow64FsRedirection, and Wow64RevertWow64FsRedirection functions.
Disabling file system redirection affects all file operations performed by the calling thread, 
so it should be disabled only when necessary for a single CreateFile call and re-enabled again immediately after the function returns.
Disabling file system redirection for longer periods can prevent 32-bit applications from loading system DLLs, causing the applications to fail.

32-bit applications can access the native system directory by substituting %windir%\Sysnative for %windir%\System32. 
WOW64 recognizes Sysnative as a special alias used to indicate that the file system should not redirect the access. 
This mechanism is flexible and easy to use, therefore, it is the recommended mechanism to bypass file system redirection. 
Note that 64-bit applications cannot use the Sysnative alias as it is a virtual directory not a real one.

Windows Server 2003 and Windows XP: The Sysnative alias was added starting with Windows Vista.

https://docs.microsoft.com/zh-cn/windows/win32/winprog64/file-system-redirector
*/

#pragma once

class Redirector
{

};
