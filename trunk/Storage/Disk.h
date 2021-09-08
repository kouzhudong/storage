#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


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
