/*

ʹ��ID�������ļ���FILE_OPEN_BY_FILE_ID��.
��ʵ����������صģ���Ϊ����Ǹ�ID�Ӻζ������϶����ǵô򿪡�
������������δ򿪺��ϴδ򿪵�Ȩ�޺͹��ܲ�һ�������Ի�Ҫ���أ�
���صð취�ǣ�

Windows-driver-samples/blob/master/filesys/miniFilter/NameChanger/nccreate.c
if (FlagOn( Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID )) {
        ReturnValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto NcPreCreateCleanup;
    }

Windows-driver-samples/blob/master/filesys/miniFilter/delete/delete.c��DfDetectDeleteByFileId ������

�㿴��������̶��Ź��ˣ����������
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
