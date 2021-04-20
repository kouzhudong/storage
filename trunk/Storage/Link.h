/*
���İ�����Ӳ���ӣ���ݷ�ʽ�����������������ӣ���������/���ص㣩����������ھ��֡�

˵������б�Ҫ˵˵���ǵ����𣬲�Ȼ�����±���˵����������

1.Ӳ��������Ӳ�����Ǵ��̺;�һ������ġ�
2.�����ӣ������ص㣬�����������ӣ�������ʵ���ǳ�����㣬���������ص��Ǹ����֣�NTSTATUS���͵�STATUS_REPARSE����
3.��ݷ�ʽ������ϵͳӦ�ò�ʵ�ֵĶ���������shell��Χ�ڡ�

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
