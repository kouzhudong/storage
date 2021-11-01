/*
这里定义操作磁盘（文件系统）的一些数据结构。

FAT是开源的，见：Windows-driver-samples\filesys\fastfat\fat.h.

这里主要是一些NTFS的结构的定义，参考：\Win2K3\NT\base\fs\ntfs\ntfs.h

注意：FAT和NTFS的一些结构还是不一样的，比如：_PACKED_BOOT_SECTOR。
*/


#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////
/*
摘自：
NTFS_On_Disk_Structure.pdf
https://www.installsetupconfig.com/win32programming/windowsvolumeapis1_22.html
*/


typedef struct {
    ULONG Type;
    USHORT UsaOffset;
    USHORT UsaCount;
    USN Usn;
} NTFS_RECORD_HEADER, * PNTFS_RECORD_HEADER;

typedef struct {
    NTFS_RECORD_HEADER Ntfs;
    USHORT SequenceNumber;
    USHORT LinkCount;
    USHORT AttributesOffset;
    USHORT Flags;               // 0x0001 = InUse, 0x0002 = Directory
    ULONG BytesInUse;
    ULONG BytesAllocated;
    ULONGLONG BaseFileRecord;
    USHORT NextAttributeNumber;
} FILE_RECORD_HEADER, * PFILE_RECORD_HEADER;


//////////////////////////////////////////////////////////////////////////////////////////////////
//摘自：\Win2K3\NT\base\fs\ntfs\ntfs.h


typedef LONGLONG LCN;
typedef LCN * PLCN;


#pragma pack(4)
typedef struct _PACKED_BIOS_PARAMETER_BLOCK {
    UCHAR  BytesPerSector[2];                               //  offset = 0x000
    UCHAR  SectorsPerCluster[1];                            //  offset = 0x002
    UCHAR  ReservedSectors[2];                              //  offset = 0x003 (zero)
    UCHAR  Fats[1];                                         //  offset = 0x005 (zero)
    UCHAR  RootEntries[2];                                  //  offset = 0x006 (zero)
    UCHAR  Sectors[2];                                      //  offset = 0x008 (zero)
    UCHAR  Media[1];                                        //  offset = 0x00A
    UCHAR  SectorsPerFat[2];                                //  offset = 0x00B (zero)
    UCHAR  SectorsPerTrack[2];                              //  offset = 0x00D
    UCHAR  Heads[2];                                        //  offset = 0x00F
    UCHAR  HiddenSectors[4];                                //  offset = 0x011 (zero)
    UCHAR  LargeSectors[4];                                 //  offset = 0x015 (zero)
} PACKED_BIOS_PARAMETER_BLOCK;                              //  sizeof = 0x019
#pragma pack()

static_assert(0x019 == sizeof(PACKED_BIOS_PARAMETER_BLOCK), "");

typedef PACKED_BIOS_PARAMETER_BLOCK * PPACKED_BIOS_PARAMETER_BLOCK;


#pragma pack(1)
typedef struct BIOS_PARAMETER_BLOCK {
    USHORT BytesPerSector;
    UCHAR  SectorsPerCluster;
    USHORT ReservedSectors;
    UCHAR  Fats;
    USHORT RootEntries;
    USHORT Sectors;
    UCHAR  Media;
    USHORT SectorsPerFat;
    USHORT SectorsPerTrack;
    USHORT Heads;
    ULONG  HiddenSectors;
    ULONG  LargeSectors;
} BIOS_PARAMETER_BLOCK;
#pragma pack()

static_assert(0x019 == sizeof(BIOS_PARAMETER_BLOCK), "");

typedef BIOS_PARAMETER_BLOCK * PBIOS_PARAMETER_BLOCK;


#pragma pack(4)
typedef struct _PACKED_BOOT_SECTOR {
    UCHAR Jump[3];                                                              //  offset = 0x000
    UCHAR Oem[8];                                                               //  offset = 0x003
    PACKED_BIOS_PARAMETER_BLOCK PackedBpb;                                      //  offset = 0x00B
    UCHAR Unused[4];                                                            //  offset = 0x024
    LONGLONG NumberSectors;                                                     //  offset = 0x028
    LCN MftStartLcn;                                                            //  offset = 0x030
    LCN Mft2StartLcn;                                                           //  offset = 0x038
    CHAR ClustersPerFileRecordSegment;                                          //  offset = 0x040
    UCHAR Reserved0[3];
    CHAR DefaultClustersPerIndexAllocationBuffer;                               //  offset = 0x044
    UCHAR Reserved1[3];
    LONGLONG SerialNumber;                                                      //  offset = 0x048
    ULONG Checksum;                                                             //  offset = 0x050
    UCHAR BootStrap[0x200 - 0x054];                                             //  offset = 0x054
} PACKED_BOOT_SECTOR;                                                           //  sizeof = 0x200
#pragma pack()

static_assert(0x200 == sizeof(PACKED_BOOT_SECTOR), "");

typedef PACKED_BOOT_SECTOR * PPACKED_BOOT_SECTOR;


//////////////////////////////////////////////////////////////////////////////////////////////////
//一下结构是自己定义的。


#pragma pack(1)
typedef struct _BPB { //BIOS parameter block (BPB)
    BYTE Bytes_Per_Sector[2];
    BYTE Sectors_Per_Cluster;
    BYTE Reserved_Sectors[2];
    BYTE must_be_0_1[3];
    BYTE must_be_0_2[2];
    BYTE Media_Descriptor;
    BYTE must_be_0_3[2];
    BYTE Not_used_1[2];
    BYTE Not_used_2[2];
    BYTE Not_used_3[4];
    BYTE must_be_0_4[4];
    BYTE Not_used_4[4];
    BYTE Total_Sectors[8];
    BYTE LCN_MFT[8];//Logical Cluster Number for the File $MFT.
    BYTE LCN_MFTMirr[8];//Logical Cluster Number for the File $MFTMirr. 
    BYTE Clusters_Per_MFT_Record;
    BYTE Not_used_5[3];
    BYTE Clusters_Per_Index_Buffer;
    BYTE Not_used_6[3];
    BYTE VSN[8];//Volume Serial Number. The volume’s serial number.
    BYTE Not_used_7[4];
} BPB, * PBPB;//总大小是：25。
#pragma pack()


#pragma pack(1)
typedef struct _BPB1 { //BIOS parameter block (BPB)
    short int Bytes_Per_Sector;
    BYTE Sectors_Per_Cluster;
    short int Reserved_Sectors;
    BYTE must_be_0_1[5];
    BYTE Media_Descriptor;
    BYTE must_be_0_2[18];
    unsigned __int64  Total_Sectors;
    unsigned __int64 LCN_MFT;//Logical Cluster Number for the File $MFT. 
    unsigned __int64 LCN_MFTMirr;//Logical Cluster Number for the File $MFTMirr. 
    BYTE Clusters_Per_MFT_Record;
    BYTE Not_used_3[3];
    BYTE Clusters_Per_Index_Buffer;
    BYTE Not_used_6[3];
    BYTE VSN[8];//Volume Serial Number. The volume’s serial number.
    BYTE Not_used_7[4];
} BPB1, * PBPB1;//总大小是：25。
#pragma pack()


#pragma pack(1)
typedef struct _NTFS_Boot_Sector { //Byte Offset
    BYTE Jump_instruction[3];      //0x00  
    char OEM_ID[8];                //0x03
    BPB1 BPB;//BPB[25];                  //0x0B
    BYTE Extended_BPB[48];         //0x24
    BYTE Bootstrap_code[426];      //0x54
    BYTE End_of_sector_marker[2];  //0x01FE
} NTFS_Boot_Sector, * PNTFS_Boot_Sector;
#pragma pack()


#define g_PhysicalDrive0 L"\\\\.\\PhysicalDrive0"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
int WINAPI ReadDiskSector(_In_ LPCWSTR lpFileName,
                          _In_ LONGLONG QuadPart,
                          _Out_writes_opt_(nNumberOfBytesToRead) LPVOID lpBuffer,
                          _In_ DWORD nNumberOfBytesToRead
);

EXTERN_C
__declspec(dllexport)
int WINAPI ReadMBR(_In_ LPCWSTR lpFileName,
                   _Out_writes_opt_(nNumberOfBytesToRead) LPVOID lpBuffer,
                   _In_ DWORD nNumberOfBytesToRead
);
