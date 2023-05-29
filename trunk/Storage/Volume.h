/*

VolumeMountPoint是本文必不可少的一个内容，还有网络盘符也可考虑包含。

有用的命令：
fsutil.exe reparsePoint query "C:\Documents and Settings"
fsutil reparsePoint query C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\procexp.exe
fsutil.exe usn queryJournal c:

解惑：
查看C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\procexp.exe，文件大小为0，且还能正常运行，
再看它不是快捷方式，也不是硬链接，但是是软连接（不是说只能是目录吗？）。
其实它指向的是：C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_2023.4.2.0_x64__8wekyb3d8bbwe\Tools\procexp.exe

"C:\Documents and Settings" 和 C:\System Volume Information
这两个目录，赋予适当的安全配置之后，是可以在资源管理器中打开的。

基本常识之问：
1.系统盘一定是C盘吗？
2.系统卷一定是\Device\HarddiskVolume1吗？
3.系统盘一定是\Device\Harddisk1吗？
*/

#pragma once

#include "pch.h"

typedef struct _FILE_SYSTEM_RECOGNITION_STRUCTURE
{
    UCHAR  Jmp[3];
    UCHAR  FsName[8];
    UCHAR  MustBeZero[5];
    ULONG  Identifier;
    USHORT Length;
    USHORT Checksum;
} FILE_SYSTEM_RECOGNITION_STRUCTURE, * PFILE_SYSTEM_RECOGNITION_STRUCTURE;
