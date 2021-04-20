/*
NTFS metadata files:

$Mft
$LogFile
$Volume
$AttrDef
$Bitmap
$Boot
$BadClus
$Secure
$UpCase
$Extend

https://docs.microsoft.com/en-us/sysinternals/downloads/contig
*/

/*
Master File Table
05/31/2018
2 minutes to read

[This document applies only to version 3 of NTFS volumes.]

The master file table (MFT) stores the information required to retrieve files from an NTFS partition.

A file may have one or more MFT records, and can contain one or more attributes.
In NTFS, a file reference is the MFT segment reference of the base file record. 
For more information, see MFT_SEGMENT_REFERENCE.

The MFT contains file record segments; 
the first 16 of these are reserved for special files, such as the following:

0: MFT ($Mft)
5: root directory (\)
6: volume cluster allocation file ($Bitmap)
8: bad-cluster file ($BadClus)
Each file record segment starts with a file record segment header. 
For more information, see FILE_RECORD_SEGMENT_HEADER. 
Each file record segment is followed by one or more attributes. 
Each attribute starts with an attribute record header. 
For more information, see ATTRIBUTE_RECORD_HEADER. 
The attribute record includes the attribute type (such as $DATA or $BITMAP), an optional name, and the attribute value. 
The user data stream is an attribute, as are all streams. 
The attribute list is terminated with 0xFFFFFFFF ($END).

The following are some example attributes.

The $Mft file contains an unnamed $DATA attribute that is the sequence of MFT record segments, in order.
The $Mft file contains an unnamed $BITMAP attribute that indicates which MFT records are in use.
The $Bitmap file contains an unnamed $DATA attribute that indicates which clusters are in use.
The $BadClus file contains a $DATA attribute named $BAD that contains an entry that corresponds to each bad cluster.
When there is no more space for storing attributes in the file record segment, 
additional file record segments are allocated and inserted in the first (or base) file record segment in an attribute called the attribute list.
The attribute list indicates where each attribute associated with the file can be found. 
This includes all attributes in the base file record, except for the attribute list itself. 
For more information, see ATTRIBUTE_LIST_ENTRY.

Structures related to the MFT include the following:

ATTRIBUTE_LIST_ENTRY
ATTRIBUTE_RECORD_HEADER
FILE_NAME
FILE_RECORD_SEGMENT_HEADER
MFT_SEGMENT_REFERENCE
MULTI_SECTOR_HEADER
STANDARD_INFORMATION

https://docs.microsoft.com/en-us/windows/win32/devnotes/master-file-table
*/

#pragma once

class MetaData
{

};
