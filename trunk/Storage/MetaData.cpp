#include "pch.h"
#include "MetaData.h"
#include "Disk.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
int WINAPI GetMft(_In_ LPCWSTR VolumeName)
/*
功能：定位/获取一个ntfs/refs卷下的mft元文件。
*/
{
    BYTE inBuffer[512] = {0};

    int x = ReadMBR(VolumeName, &inBuffer, sizeof(inBuffer));

    PPACKED_BOOT_SECTOR bs = (PPACKED_BOOT_SECTOR)&inBuffer;

    PBIOS_PARAMETER_BLOCK bpb = (PBIOS_PARAMETER_BLOCK)&bs->PackedBpb;

    LONGLONG QuadPart = bs->MftStartLcn * bpb->SectorsPerCluster * bpb->BytesPerSector;

    BYTE mft[512] = {0};
    x = ReadDiskSector(VolumeName, QuadPart, mft, sizeof(mft));

    PFILE_RECORD_HEADER pfrh = (PFILE_RECORD_HEADER)&mft;

    return 0;
}
