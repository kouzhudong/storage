/*

使用ID号来打开文件（FILE_OPEN_BY_FILE_ID）.
其实这个不用拦截的，因为你的那个ID从何而来，肯定还是得打开。
不过，都怕这次打开和上次打开得权限和功能不一样，所以还要拦截，
拦截得办法是：

Windows-driver-samples/blob/master/filesys/miniFilter/NameChanger/nccreate.c
if (FlagOn( Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID )) {
        ReturnValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto NcPreCreateCleanup;
    }

Windows-driver-samples/blob/master/filesys/miniFilter/delete/delete.c的DfDetectDeleteByFileId 函数。

你看，这个工程都放过了，这个操作：
Windows-driver-samples/blob/master/filesys/miniFilter/simrep/simrep.c
    //  Don't reparse an open by ID because it is not possible to determine create path intent.
    if (FlagOn( irpSp->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID )) {
        goto SimRepPreNetworkQueryOpenCleanup;
    }
*/


#pragma once

class File
{

};
