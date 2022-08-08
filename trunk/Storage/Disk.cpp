#include "pch.h"
#include "Disk.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/* The code of interest is in the subroutine GetDriveGeometry.
   The code in main shows how to interpret the results of the call. 
*/


EXTERN_C
__declspec(dllexport)
BOOL WINAPI GetDriveGeometry(LPWSTR wszPath, DISK_GEOMETRY * pdg)
/*
The following example demonstrates how to retrieve information about the first physical drive in the system.
It uses the CreateFile function to retrieve the device handle to the first physical drive,
and then uses DeviceIoControl with the IOCTL_DISK_GET_DRIVE_GEOMETRY control code to fill a DISK_GEOMETRY structure with information about the drive.

https://docs.microsoft.com/zh-cn/windows/win32/devio/calling-deviceiocontrol?redirectedfrom=MSDN
*/
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined 
    BOOL bResult = FALSE;                   // results flag
    DWORD junk = 0;                         // discard results

    hDevice = CreateFileW(wszPath,          // drive to open
                          0,                // no access to the drive
                          FILE_SHARE_READ | // share mode
                          FILE_SHARE_WRITE,
                          NULL,             // default security attributes
                          OPEN_EXISTING,    // disposition
                          0,                // file attributes
                          NULL);            // do not copy file attributes

    if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
    {
        return (FALSE);
    }

    bResult = DeviceIoControl(hDevice,                       // device to be queried
                              IOCTL_DISK_GET_DRIVE_GEOMETRY, // operation to perform
                              NULL, 0,                       // no input buffer
                              pdg, sizeof(*pdg),            // output buffer
                              &junk,                         // # bytes returned
                              (LPOVERLAPPED)NULL);          // synchronous I/O

    CloseHandle(hDevice);

    return (bResult);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
int WINAPI ReadDiskSector(_In_ LPCWSTR lpFileName,
                          _In_ LONGLONG QuadPart,
                          _Out_writes_opt_(nNumberOfBytesToRead) LPVOID lpBuffer,
                          _In_ DWORD nNumberOfBytesToRead
)
/*
功能：读取MBR。

参数说明：
lpFileName：不可取L"\\\\.\\PhysicalDriveX",尽管这样也能获取到值，但是不是合法的MBR，也和winhex的不一样。
            建议取：L"\\\\.\\x:"。

http://technet.microsoft.com/en-us/library/cc781134(v=ws.10).aspx
http://ntfs.com/ntfs-partition-boot-sector.htm

FSCTL_GET_NTFS_VOLUME_DATA
NTFS_VOLUME_DATA_BUFFER

made by correy
made at 2014.11.28
*/
{
    //DebugBreak();

    if (!SetCurrentProcessPrivilege(SE_DEBUG_NAME, TRUE)) {
        return FALSE;
    }

    HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined 
    BOOL bResult = FALSE;                   // results flag

    hDevice = CreateFileW(lpFileName,         // drive to open g_PhysicalDrive0
                          GENERIC_READ,     // no access to the drive
                          FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
                          NULL,             // default security attributes
                          OPEN_EXISTING,    // disposition
                          0,                // file attributes
                          NULL);            // do not copy file attributes
    if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
    {
        return (FALSE);
    }

    LARGE_INTEGER  liDistanceToMove = {0};
    liDistanceToMove.QuadPart = QuadPart;
    LARGE_INTEGER lpNewFilePointer = {0};
    SetFilePointerEx(hDevice, liDistanceToMove, &lpNewFilePointer, FILE_BEGIN);
    
    DWORD nBytesRead = 0;
    bResult = ReadFile(hDevice, lpBuffer, nNumberOfBytesToRead, &nBytesRead, NULL);
    if (bResult == 0) {//CreateFileW的第一个参数为0，导致这里：5 拒绝访问。
        int x = GetLastError();
        CloseHandle(hDevice);
        return (FALSE);
    }

    PPACKED_BOOT_SECTOR bs = (PPACKED_BOOT_SECTOR)lpBuffer;
    _ASSERTE(bs);

    PBIOS_PARAMETER_BLOCK bpb = (PBIOS_PARAMETER_BLOCK)&bs->PackedBpb;

    CloseHandle(hDevice);

    return 0;
}


EXTERN_C
__declspec(dllexport)
int WINAPI ReadMBR(_In_ LPCWSTR lpFileName,
                   _Out_writes_opt_(nNumberOfBytesToRead) LPVOID lpBuffer,
                   _In_ DWORD nNumberOfBytesToRead
)
{
    return ReadDiskSector(lpFileName, 0, lpBuffer, nNumberOfBytesToRead);
}


EXTERN_C
__declspec(dllexport)
int WINAPI WriteMBR(_In_ LPCWSTR lpFileName)
/*
功能：写MBR。

参数说明：
lpFileName：不可取L"\\\\.\\PhysicalDriveX",尽管这样也能写一些，但是有许多的限制，更多的是失败。
            建议取：L"\\\\.\\x:"。

此函数在Windows 10上测试成功，写两个扇区。
*/
{
    //DebugBreak();

    if (!SetCurrentProcessPrivilege(SE_DEBUG_NAME, TRUE)) {
        return FALSE;
    }

    if (!SetCurrentProcessPrivilege(SE_BACKUP_NAME, TRUE)) {
        return FALSE;
    }

    if (!SetCurrentProcessPrivilege(SE_RESTORE_NAME, TRUE)) {
        return FALSE;
    }

    if (!SetCurrentProcessPrivilege(SE_MANAGE_VOLUME_NAME, TRUE)) {
        return FALSE;
    }

    //if (!SetCurrentProcessPrivilege(SE_TCB_NAME, TRUE)) {
    //    return FALSE;
    //}

    HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined 
    BOOL bResult = FALSE;                   // results flag

    hDevice = CreateFileW(lpFileName,         // drive to open
                          GENERIC_WRITE,     // no access to the drive GENERIC_ALL
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,  // share mode
                          NULL,             // default security attributes
                          OPEN_EXISTING,    // disposition
                          0,                // file attributes
                          NULL);            // do not copy file attributes
    if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
    {
        printf("CreateFile LastError:%d", GetLastError());
        return (FALSE);
    }

    int x = IOCTL_DISK_GET_DRIVE_GEOMETRY;//0x00070000
    x = FSCTL_LOCK_VOLUME;//0x00090018
    x = FSCTL_DISMOUNT_VOLUME;//0x00090020

    LPDWORD dummy = new DWORD;
    BOOL ret = DeviceIoControl(hDevice,
                               FSCTL_LOCK_VOLUME,
                               NULL,
                               0,
                               NULL,
                               0,
                               dummy,
                               NULL);

    ret = DeviceIoControl(hDevice,
                          FSCTL_DISMOUNT_VOLUME,
                          NULL,
                          0,
                          NULL,
                          0,
                          dummy,
                          NULL);

    DISK_GEOMETRY lpOutBuffer = {0};
    DWORD nOutBufferSize = sizeof(DISK_GEOMETRY);
    DWORD BytesReturned = 0;
    ret = DeviceIoControl(hDevice,
                          IOCTL_DISK_GET_DRIVE_GEOMETRY,
                          NULL,
                          0,
                          (LPVOID)&lpOutBuffer,             // output buffer
                          nOutBufferSize,           // size of output buffer
                          &BytesReturned,        // number of bytes returned,
                          NULL);

    SetFilePointer(hDevice, 0, 0, 0);

    BYTE inBuffer[1024] = {0};//一个扇区一般是512字节。这里是两个扇区。
    DWORD nBytesRead = 0;
    bResult = WriteFile(hDevice, &inBuffer, sizeof(inBuffer), &nBytesRead, NULL);
    if (bResult == 0) {//CreateFileW的第一个参数为0，导致这里：5 拒绝访问。
        printf("WriteFile LastError:%d", GetLastError());
        CloseHandle(hDevice);
        return (FALSE);
    }

    CloseHandle(hDevice);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD GetPhysicalDriveSerialNumber(UINT nDriveNumber IN, CString & strSerialNumber OUT)
/*
功能：获取磁盘的序列号。

注释：
在VMWARE中是没有序列号的。
这是不是检查VMARE虚拟机的一个办法？

用法示例：
    CString strSerialNumber;
    DWORD dwRet = GetPhysicalDriveSerialNumber(0, strSerialNumber);
    if (NO_ERROR != dwRet) {
        CString strError;
        strError.Format(_T("GetPhysicalDriveSerialNumber failed. Error: %u"), dwRet);
    }

验证命令：
wmic diskdrive get serialnumber
wmic path win32_physicalmedia get SerialNumber
wmic path Win32_DiskDrive get SerialNumber
以上三个命令都是一样的，都是显示所有磁盘的序列号。

http://codexpert.ro/blog/2013/10/26/get-physical-drive-serial-number-part-1/
*/
{
    DWORD dwRet = NO_ERROR;
    strSerialNumber.Empty();

    // Format physical drive path (may be '\\.\PhysicalDrive0', '\\.\PhysicalDrive1' and so on).
    CString strDrivePath;
    strDrivePath.Format(_T("\\\\.\\PhysicalDrive%u"), nDriveNumber);

    // Get a handle to physical drive
    HANDLE hDevice = ::CreateFile(strDrivePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hDevice)
        return ::GetLastError();

    // Set the input data structure
    STORAGE_PROPERTY_QUERY storagePropertyQuery;
    ZeroMemory(&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY));
    storagePropertyQuery.PropertyId = StorageDeviceProperty;
    storagePropertyQuery.QueryType = PropertyStandardQuery;

    // Get the necessary output buffer size
    STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader = {0};
    DWORD dwBytesReturned = 0;
    if (!::DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
                           &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
                           &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER),
                           &dwBytesReturned, NULL)) {
        dwRet = ::GetLastError();
        ::CloseHandle(hDevice);
        return dwRet;
    }

    // Alloc the output buffer
    const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
    BYTE * pOutBuffer = new BYTE[dwOutBufferSize];
    ZeroMemory(pOutBuffer, dwOutBufferSize);

    // Get the storage device descriptor
    if (!::DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
                           &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
                           pOutBuffer, dwOutBufferSize,
                           &dwBytesReturned, NULL)) {
        dwRet = ::GetLastError();
        delete[]pOutBuffer;
        ::CloseHandle(hDevice);
        return dwRet;
    }

    // Now, the output buffer points to a STORAGE_DEVICE_DESCRIPTOR structure
    // followed by additional info like vendor ID, product ID, serial number, and so on.
    STORAGE_DEVICE_DESCRIPTOR * pDeviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR *)pOutBuffer;
    const DWORD dwSerialNumberOffset = pDeviceDescriptor->SerialNumberOffset;
    if (dwSerialNumberOffset != 0) {// Finally, get the serial number
        strSerialNumber = CString(pOutBuffer + dwSerialNumberOffset);
        //MessageBox(0, 0, strSerialNumber.GetBuffer(), 0);
    }

    // Do cleanup and return
    delete[]pOutBuffer;
    ::CloseHandle(hDevice);
    return dwRet;
}


void GetPhysicalDriveSerialNumberWithWMI(UINT nDriveNumber IN, CString & strSerialNumber OUT)
//http://codexpert.ro/blog/2013/10/27/get-physical-drive-serial-number-part-2/
{
    strSerialNumber.Empty();

    // Format physical drive path (may be '\\.\PhysicalDrive0', '\\.\PhysicalDrive1' and so on).
    CString strDrivePath;
    strDrivePath.Format(_T("\\\\.\\PhysicalDrive%u"), nDriveNumber);

    // 2. Set the default process security level 
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa393617(v=vs.85).aspx
    HRESULT hr = ::CoInitializeSecurity(
        NULL,                        // Security descriptor    
        -1,                          // COM negotiates authentication service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication level for proxies
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation level for proxies
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities of the client or server
        NULL);                       // Reserved

    ATLENSURE_SUCCEEDED(hr);

    // 3. Create a connection to WMI namespace
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa389749(v=vs.85).aspx

    // 3.1. Initialize the IWbemLocator interface
    CComPtr<IWbemLocator> pIWbemLocator;
    hr = ::CoCreateInstance(CLSID_WbemLocator, 0,
                            CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pIWbemLocator);

    ATLENSURE_SUCCEEDED(hr);

    // 3.2. Call IWbemLocator::ConnectServer for connecting to WMI 
    CComPtr<IWbemServices> pIWbemServices;
    hr = pIWbemLocator->ConnectServer((const BSTR)L"ROOT\\CIMV2",
                                      NULL, NULL, 0, NULL, 0, 0, &pIWbemServices);

    ATLENSURE_SUCCEEDED(hr);

    // 4. Set the security levels on WMI connection
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa393619(v=vs.85).aspx
    hr = ::CoSetProxyBlanket(
        pIWbemServices,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    ATLENSURE_SUCCEEDED(hr);

    // 5. Execute a WQL (WMI Query Language) query to get physical media info
    const BSTR szQueryLanguage = (const BSTR)L"WQL";
    const BSTR szQuery = (const BSTR)L"SELECT Tag, SerialNumber FROM Win32_PhysicalMedia";
    CComPtr<IEnumWbemClassObject> pIEnumWbemClassObject;
    hr = pIWbemServices->ExecQuery(
        szQueryLanguage,                                       // Query language
        szQuery,                                               // Query
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   // Flags
        NULL,                                                  // Context
        &pIEnumWbemClassObject);                               // Enumerator

    ATLENSURE_SUCCEEDED(hr);

    // 6. Get each enumerator element until find the desired physical drive 
    ULONG uReturn = 0;
    while (pIEnumWbemClassObject) {
        CComPtr<IWbemClassObject> pIWbemClassObject;
        hr = pIEnumWbemClassObject->Next(WBEM_INFINITE, 1, &pIWbemClassObject, &uReturn);
        if (0 == uReturn || FAILED(hr))
            break;

        variant_t vtTag;           // unique tag, e.g. '\\.\PHYSICALDRIVE0'
        variant_t vtSerialNumber;  // manufacturer-provided serial number

        hr = pIWbemClassObject->Get(L"Tag", 0, &vtTag, NULL, NULL);
        ATLENSURE_SUCCEEDED(hr);

        CString strTag(vtTag.bstrVal);
        if (!strTag.CompareNoCase(strDrivePath)) // physical drive found
        {
            hr = pIWbemClassObject->Get(L"SerialNumber", 0, &vtSerialNumber, NULL, NULL);
            ATLENSURE_SUCCEEDED(hr);
            strSerialNumber = vtSerialNumber.bstrVal; // get the serial number
            break;
        }
    }
}


int GetPhysicalDriveSerialNumberWithWMITest(int argc, _TCHAR * argv[])
{
    CString strResult;
    try {
        // 1. Initialize COM 
        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa390885(v=vs.85).aspx
        HRESULT hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);

        ATLENSURE_SUCCEEDED(hr);

        CString strSerialNumber;
        UINT nDriveNumber = 0;
        GetPhysicalDriveSerialNumber(nDriveNumber, strSerialNumber);
    #pragma prefast(push)
    #pragma prefast(disable: 6284, "XXXXX")
        strResult.Format(L"Serial number for drive #%u is %s", nDriveNumber, strSerialNumber);
    #pragma prefast(pop)   

    } catch (CAtlException & e) {
        strResult.Format(_T("Get serial number failure. Error code: 0x%08X"), (HRESULT)e);
    }

    // Show result
    ::MessageBox(NULL, strResult, _T("Serial number demo"), MB_OK);

    // Uninitialize COM
    ::CoUninitialize();
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
