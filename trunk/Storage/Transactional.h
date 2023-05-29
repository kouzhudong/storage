/*
Kernel Transaction Manager

0:000> x kernel32!*Transacted*
00007ffa`a8603ccf KERNEL32!CreateSymbolicLinkTransactedW$fin$0 (void)
00007ffa`a8607e44 KERNEL32!GetFullPathNameTransactedW$fin$0 (void)
00007ffa`a85d85db KERNEL32!FindFirstFileNameTransactedW$fin$0 (void)
00007ffa`a86040ec KERNEL32!MoveFileTransactedA$fin$0 (void)
00007ffa`a85d8296 KERNEL32!GetFullPathNameTransactedA$fin$0 (void)
00007ffa`a85c9100 KERNEL32!MoveFileTransactedW$fin$0 (void)
00007ffa`a8603318 KERNEL32!CreateDirectoryTransactedW$fin$0 (void)
00007ffa`a8602764 KERNEL32!CopyFileTransactedA$fin$0 (void)
00007ffa`a85c9171 KERNEL32!DeleteFileTransactedW$fin$0 (void)
00007ffa`a85d86cd KERNEL32!FindFirstFileTransactedA$fin$0 (void)
00007ffa`a85c48f0 KERNEL32!DeleteFileTransactedW (void)
00007ffa`a86047de KERNEL32!SetFileAttributesTransactedW$fin$0 (void)
00007ffa`a8603fad KERNEL32!GetFileAttributesTransactedW$fin$0 (void)
00007ffa`a860358d KERNEL32!CreateHardLinkTransactedW$fin$0 (void)
00007ffa`a8602ab0 KERNEL32!CreateFileTransactedW$fin$0 (void)
00007ffa`a8602869 KERNEL32!CopyFileTransactedW$fin$0 (void)
00007ffa`a8601a18 KERNEL32!GetLongPathNameTransactedW$fin$0 (void)
00007ffa`a85c4530 KERNEL32!MoveFileTransactedW (void)
00007ffa`a85e13e8 KERNEL32!GetLongPathNameTransactedA$fin$0 (void)
00007ffa`a8603e51 KERNEL32!GetCompressedFileSizeTransactedW$fin$0 (void)
00007ffa`a8606f6d KERNEL32!FindFirstFileTransactedW$fin$0 (void)
00007ffa`a86033dc KERNEL32!RemoveDirectoryTransactedW$fin$0 (void)
00007ffa`a85d87ab KERNEL32!FindFirstStreamTransactedW$fin$0 (void)
00007ffa`a8602790 KERNEL32!CopyFileTransactedW (CopyFileTransactedW)
00007ffa`a86026a0 KERNEL32!CopyFileTransactedA (CopyFileTransactedA)
00007ffa`a85d84d0 KERNEL32!RemoveDirectoryTransactedA (RemoveDirectoryTransactedA)
00007ffa`a8603b60 KERNEL32!CreateSymbolicLinkTransactedA (CreateSymbolicLinkTransactedA)
00007ffa`a8603c20 KERNEL32!CreateSymbolicLinkTransactedW (CreateSymbolicLinkTransactedW)
00007ffa`a8601970 KERNEL32!GetLongPathNameTransactedW (GetLongPathNameTransactedW)
00007ffa`a85d8520 KERNEL32!FindFirstFileNameTransactedW (FindFirstFileNameTransactedW)
00007ffa`a85e1340 KERNEL32!GetLongPathNameTransactedA (GetLongPathNameTransactedA)
00007ffa`a8604134 KERNEL32!MoveFileWithProgressTransactedA (MoveFileWithProgressTransactedA)
00007ffa`a8603340 KERNEL32!RemoveDirectoryTransactedW (RemoveDirectoryTransactedW)
00007ffa`a85d86f0 KERNEL32!FindFirstStreamTransactedW (FindFirstStreamTransactedW)
00007ffa`a8604740 KERNEL32!SetFileAttributesTransactedW (SetFileAttributesTransactedW)
00007ffa`a8603ef0 KERNEL32!GetFileAttributesTransactedW (GetFileAttributesTransactedW)
00007ffa`a85e3e80 KERNEL32!CreateHardLinkTransactedA (CreateHardLinkTransactedA)
00007ffa`a86034d0 KERNEL32!CreateHardLinkTransactedW (CreateHardLinkTransactedW)
00007ffa`a85d8600 KERNEL32!FindFirstFileTransactedA (FindFirstFileTransactedA)
00007ffa`a8603d50 KERNEL32!GetCompressedFileSizeTransactedA (GetCompressedFileSizeTransactedA)
00007ffa`a8603d00 KERNEL32!DeleteFileTransactedA (DeleteFileTransactedA)
00007ffa`a85d8420 KERNEL32!CreateDirectoryTransactedA (CreateDirectoryTransactedA)
00007ffa`a8607d80 KERNEL32!GetFullPathNameTransactedW (GetFullPathNameTransactedW)
00007ffa`a86218e0 KERNEL32!_imp_MoveFileWithProgressTransactedW = <no type information>
00007ffa`a8602950 KERNEL32!CreateFileTransactedW (CreateFileTransactedW)
00007ffa`a8602890 KERNEL32!CreateFileTransactedA (CreateFileTransactedA)
00007ffa`a8604030 KERNEL32!MoveFileTransactedA (MoveFileTransactedA)
00007ffa`a85d81e0 KERNEL32!GetFullPathNameTransactedA (GetFullPathNameTransactedA)
00007ffa`a86046e0 KERNEL32!SetFileAttributesTransactedA (SetFileAttributesTransactedA)
00007ffa`a8603e80 KERNEL32!GetFileAttributesTransactedA (GetFileAttributesTransactedA)
00007ffa`a8606ea0 KERNEL32!FindFirstFileTransactedW (FindFirstFileTransactedW)
00007ffa`a8603db0 KERNEL32!GetCompressedFileSizeTransactedW (GetCompressedFileSizeTransactedW)
00007ffa`a8603250 KERNEL32!CreateDirectoryTransactedW (CreateDirectoryTransactedW)

���ƴ���	˵��
FSCTL_TXFS_CREATE_MINIVERSION
Ϊָ���ļ������µ� ΢�Ͱ汾 ��
΢�Ͱ汾�����������ڼ������ļ��Ŀ��ա� �ύ��ع�����ʱ���ᶪ��΢�Ͱ汾��
FSCTL_TXFS_GET_METADATA_INFO
�����ļ��� Transacted NTFS (TxF) Ԫ���ݣ��Լ�����ָ�� (�ļ�������� GUID ������ļ�����) ����
FSCTL_TXFS_GET_TRANSACTED_VERSION
���� TXFS_GET_TRANSACTED_VERSION �ṹ�� �ýṹ��ʶָ���ļ��������ύ�汾��������İ汾�š�
FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES
����ָ������ǰ�����������ļ����б� �������ֵ ERROR_MORE_DATA���򷵻��ڴ˵���ʱ�����ļ������б�����Ļ��������ȡ�
FSCTL_TXFS_LIST_TRANSACTIONS
����ָ����Դ�������е�ǰ�漰������������б�
FSCTL_TXFS_MODIFY_RM
Ϊ������Դ������ (RM) ������־ģʽ����־������Ϣ��
FSCTL_TXFS_QUERY_RM_INFORMATION
������Դ������ (RM) ����Ϣ��
FSCTL_TXFS_READ_BACKUP_INFORMATION
�������� NTFS (TxF) ָ���ļ����ض���Ϣ��
FSCTL_TXFS_SAVEPOINT_INFORMATION
FSCTL_TXFS_SAVEPOINT_INFORMATION���ƴ���������á�����ͻع���ָ���ı���㡣
��Ҫִ�д˲�������ʹ�����²������� DeviceIoControl ������
FSCTL_TXFS_TRANSACTION_ACTIVE
����һ������ֵ����ֵָʾ��������ʱ���������Ƿ����κ������ڻ״̬�� �˵��ý�������ֻ�����վ�
FSCTL_TXFS_WRITE_BACKUP_INFORMATION
������ NTFS (TxF) �ض���Ϣд��ָ���ļ��� TXFS_WRITE_BACKUP_INFORMATION�ṹ�� Buffer ��Ա������FSCTL_TXFS_READ_BACKUP_INFORMATION���ص�TXFS_READ_BACKUP_INFORMATION_OUT�ṹ�� Buffer ��Ա��
https://learn.microsoft.com/zh-cn/windows/win32/fileio/transactional-ntfs-control-codes
*/


#pragma once

class Transactional
{

};

