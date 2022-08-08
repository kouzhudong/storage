#include "Disk.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetDriveGeometryTest(int argc, wchar_t * argv[])
{
    DISK_GEOMETRY pdg = {0}; // disk drive geometry structure
    BOOL bResult = FALSE;      // generic results flag
    ULONGLONG DiskSize = 0;    // size of the drive, in bytes

    bResult = GetDriveGeometry((LPWSTR)g_PhysicalDrive0, &pdg);

    if (bResult) {
        wprintf(L"Drive path      = %ws\n", g_PhysicalDrive0);
        wprintf(L"Cylinders       = %I64d\n", pdg.Cylinders.QuadPart);
        wprintf(L"Tracks/cylinder = %ld\n", (ULONG)pdg.TracksPerCylinder);
        wprintf(L"Sectors/track   = %ld\n", (ULONG)pdg.SectorsPerTrack);
        wprintf(L"Bytes/sector    = %ld\n", (ULONG)pdg.BytesPerSector);

        DiskSize = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder *
            (ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
        wprintf(L"Disk size       = %I64d (Bytes)\n"
                L"                = %.2f (Gb)\n",
                DiskSize, (double)DiskSize / (ULONGLONG)(1024 * 1024 * 1024));
    } else {
        wprintf(L"GetDriveGeometry failed. Error %ld.\n", GetLastError());
    }

    return ((int)bResult);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
