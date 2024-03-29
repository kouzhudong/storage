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

/*
确定目录是否是装载的文件夹
项目
2022/09/22

例如，在使用限制为一个卷的备份或搜索应用程序时，确定目录是装载的文件夹非常有用。 
如果使用 SetVolumeMountPoint 等函数为应用程序限制的卷上的其他卷创建装载的文件夹，则此类应用程序可以访问有关多个卷的信息。 
有关详细信息，请参阅 创建装载的文件夹。

若要确定指定的目录是否是装载的文件夹，请首先调用 GetFileAttributes 函数并检查返回值中的 FILE_ATTRIBUTE_REPARSE_POINT 标志，以查看该目录是否具有关联的重新分析点。
如果这样做，请使用 FindFirstFile 和 FindNextFile 函数获取WIN32_FIND_DATA结构的 dwReserved0 成员中的重新分析标记。 
若要确定重新分析点是否是装载的文件夹 (而不是某种形式的重新分析点) ，请测试标记值是否等于值 IO_REPARSE_TAG_MOUNT_POINT。 
有关详细信息，请参阅 重新分析点。

若要获取已装载文件夹的目标卷，请使用 GetVolumeNameForVolumeMountPoint 函数。

以类似的方式，可以通过测试标记值是否 IO_REPARSE_TAG_SYMLINK来确定重新分析点是否为符号链接。

https://learn.microsoft.com/zh-cn/windows/win32/fileio/determining-whether-a-directory-is-a-volume-mount-point
*/

/*

FileReparsePointInformation
https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ifs/irp-mj-directory-control
https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-directory-control
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class

FILE_REPARSE_POINT_INFORMATION
https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_reparse_point_information
https://learn.microsoft.com/en-us/previous-versions/mt812582(v=vs.85)
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
