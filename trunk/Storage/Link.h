/*
本文包括：硬链接，快捷方式，但不包括，软连接（符号链接/挂载点），这个内容在卷部分。

说到这里，有必要说说它们的区别，不然，恐怕别人说不够义气。

1.硬链接属于硬件，是磁盘和卷一个级别的。
2.软连接，即挂载点，又名符号链接，在驱动实现是冲解析点，即驱动返回的那个数字（NTSTATUS类型的STATUS_REPARSE）。
3.快捷方式，操作系统应用层实现的东西，属于shell范围内。

There are three types of file links supported in the NTFS file system: hard links, junctions, and symbolic links. 
This topic is an overview of hard links and junctions. 
For information about symbolic links, see Creating Symbolic Links.

A junction (also called a soft link) differs from a hard link in that the storage objects it references are separate directories, 
and a junction can link directories located on different local volumes on the same computer. 
Otherwise, junctions operate identically to hard links. 
Junctions are implemented through reparse points.

https://docs.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions
*/

#pragma once

class Link
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////////////////////////////
