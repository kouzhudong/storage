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
        //int x = GetLastError();
        CloseHandle(hDevice);
        return (FALSE);
    }

    PPACKED_BOOT_SECTOR bs = (PPACKED_BOOT_SECTOR)lpBuffer;
    _ASSERTE(bs);

    //PBIOS_PARAMETER_BLOCK bpb = (PBIOS_PARAMETER_BLOCK)&bs->PackedBpb;

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


int GetPhysicalDriveSerialNumberWithWMITest()
{
    CString strResult;

    try {        
        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa390885(v=vs.85).aspx
        HRESULT hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);// 1. Initialize COM 
        ATLENSURE_SUCCEEDED(hr);

        CString strSerialNumber;
        UINT nDriveNumber = 0;
        GetPhysicalDriveSerialNumber(nDriveNumber, strSerialNumber);
    #pragma prefast(push)
    #pragma prefast(disable: 6284, "XXXXX")
        strResult.Format(L"Serial number for drive #%u is %s", nDriveNumber, strSerialNumber.GetString());
    #pragma prefast(pop)   
    } catch (CAtlException & e) {
        strResult.Format(_T("Get serial number failure. Error code: 0x%08X"), (HRESULT)e);
    }

    ::MessageBox(NULL, strResult, _T("Serial number demo"), MB_OK);// Show result

    ::CoUninitialize();// Uninitialize COM
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI TestGetDiskFreeSpaceEx()
/*


lpDirectoryName, 如果此参数为 NULL，则该函数使用当前磁盘(程序文件所在的磁盘)的根目录。
*/
{
    LPCWSTR lpDirectoryName = nullptr;
    ULARGE_INTEGER FreeBytesAvailableToCaller;
    ULARGE_INTEGER TotalNumberOfBytes;
    ULARGE_INTEGER TotalNumberOfFreeBytes;
    BOOL b = GetDiskFreeSpaceEx(lpDirectoryName,
                                &FreeBytesAvailableToCaller,
                                &TotalNumberOfBytes,
                                &TotalNumberOfFreeBytes);

    printf("TotalNumberOfBytes:%lld GB\n", TotalNumberOfBytes.QuadPart / 1024 / 1024 / 1024);
    printf("TotalNumberOfFreeBytes:%lld GB\n", TotalNumberOfFreeBytes.QuadPart / 1024 / 1024 / 1024);
    printf("FreeBytesAvailableToCaller:%lld GB\n", FreeBytesAvailableToCaller.QuadPart / 1024 / 1024 / 1024);

    lpDirectoryName = L"c:";
    b = GetDiskFreeSpaceEx(lpDirectoryName,
                           &FreeBytesAvailableToCaller,
                           &TotalNumberOfBytes,
                           &TotalNumberOfFreeBytes);

    printf("TotalNumberOfBytes:%lld GB\n", TotalNumberOfBytes.QuadPart / 1024 / 1024 / 1024);
    printf("TotalNumberOfFreeBytes:%lld GB\n", TotalNumberOfFreeBytes.QuadPart / 1024 / 1024 / 1024);
    printf("FreeBytesAvailableToCaller:%lld GB\n", FreeBytesAvailableToCaller.QuadPart / 1024 / 1024 / 1024);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//这里是系统还原相关的代码。


/*
使用系统还原
项目
2023/10/12
5 个参与者
本文内容
示例 1：创建还原点。
示例 2：创建和取消还原点。
以下示例演示了如何使用 SRSetRestorePoint 函数创建和取消还原点。

使用系统还原的第一步是设置对 CoInitializeEx 和 CoInitializeSecurity 的 COM 调用。 
对于使用 SRSetRestorePoint 函数的任何进程，这都是必需的。 
必须允许 NetworkService、LocalService 和 System 调用该进程。 
以下 InitializeCOMSecurity 函数是初始化 COM 安全性的示例。 
可能需要将参数修改为应用程序的 CoInitializeSecurity 函数。

https://learn.microsoft.com/zh-cn/windows/win32/sr/using-system-restore
*/


BOOL InitializeCOMSecurity()
{
    // Create the security descriptor explicitly as follows because
    // CoInitializeSecurity() will not accept the relative security descriptors  
    // returned by ConvertStringSecurityDescriptorToSecurityDescriptor().

    SECURITY_DESCRIPTOR securityDesc = {0};
    EXPLICIT_ACCESS   ea[5] = {0};
    ACL * pAcl = NULL;
    ULONGLONG  rgSidBA[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = {0};
    ULONGLONG  rgSidLS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = {0};
    ULONGLONG  rgSidNS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = {0};
    ULONGLONG  rgSidPS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = {0};
    ULONGLONG  rgSidSY[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = {0};
    DWORD      cbSid = 0;
    BOOL       fRet = FALSE;
    DWORD      dwRet = ERROR_SUCCESS;
    HRESULT    hrRet = S_OK;

    // This creates a security descriptor that is equivalent to the following 
    // security descriptor definition language (SDDL) string:
    //   O:BAG:BAD:(A;;0x1;;;LS)(A;;0x1;;;NS)(A;;0x1;;;PS)(A;;0x1;;;SY)(A;;0x1;;;BA)

    // Initialize the security descriptor.
    fRet = ::InitializeSecurityDescriptor(&securityDesc, SECURITY_DESCRIPTOR_REVISION);
    if (!fRet) {
        goto exit;
    }

    // Create an administrator group security identifier (SID).
    cbSid = sizeof(rgSidBA);
    fRet = ::CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, rgSidBA, &cbSid);
    if (!fRet) {
        goto exit;
    }

    // Create a local service security identifier (SID).
    cbSid = sizeof(rgSidLS);
    fRet = ::CreateWellKnownSid(WinLocalServiceSid, NULL, rgSidLS, &cbSid);
    if (!fRet) {
        goto exit;
    }

    // Create a network service security identifier (SID).
    cbSid = sizeof(rgSidNS);
    fRet = ::CreateWellKnownSid(WinNetworkServiceSid, NULL, rgSidNS, &cbSid);
    if (!fRet) {
        goto exit;
    }

    // Create a personal account security identifier (SID).
    cbSid = sizeof(rgSidPS);
    fRet = ::CreateWellKnownSid(WinSelfSid, NULL, rgSidPS, &cbSid);
    if (!fRet) {
        goto exit;
    }

    // Create a local service security identifier (SID).
    cbSid = sizeof(rgSidSY);
    fRet = ::CreateWellKnownSid(WinLocalSystemSid, NULL, rgSidSY, &cbSid);
    if (!fRet) {
        goto exit;
    }

    // Setup the access control entries (ACE) for COM. You may need to modify 
    // the access permissions for your application. COM_RIGHTS_EXECUTE and
    // COM_RIGHTS_EXECUTE_LOCAL are the minimum access rights required.

    ea[0].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.pMultipleTrustee = NULL;
    ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)rgSidBA;

    ea[1].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.pMultipleTrustee = NULL;
    ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)rgSidLS;

    ea[2].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
    ea[2].grfAccessMode = SET_ACCESS;
    ea[2].grfInheritance = NO_INHERITANCE;
    ea[2].Trustee.pMultipleTrustee = NULL;
    ea[2].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[2].Trustee.ptstrName = (LPTSTR)rgSidNS;

    ea[3].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
    ea[3].grfAccessMode = SET_ACCESS;
    ea[3].grfInheritance = NO_INHERITANCE;
    ea[3].Trustee.pMultipleTrustee = NULL;
    ea[3].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[3].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[3].Trustee.ptstrName = (LPTSTR)rgSidPS;

    ea[4].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
    ea[4].grfAccessMode = SET_ACCESS;
    ea[4].grfInheritance = NO_INHERITANCE;
    ea[4].Trustee.pMultipleTrustee = NULL;
    ea[4].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea[4].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[4].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[4].Trustee.ptstrName = (LPTSTR)rgSidSY;

    // Create an access control list (ACL) using this ACE list.
    dwRet = ::SetEntriesInAcl(ARRAYSIZE(ea), ea, NULL, &pAcl);
    if (dwRet != ERROR_SUCCESS || pAcl == NULL) {
        fRet = FALSE;
        goto exit;
    }

    // Set the security descriptor owner to Administrators.
    fRet = ::SetSecurityDescriptorOwner(&securityDesc, rgSidBA, FALSE);
    if (!fRet) {
        goto exit;
    }

    // Set the security descriptor group to Administrators.
    fRet = ::SetSecurityDescriptorGroup(&securityDesc, rgSidBA, FALSE);
    if (!fRet) {
        goto exit;
    }

    // Set the discretionary access control list (DACL) to the ACL.
    fRet = ::SetSecurityDescriptorDacl(&securityDesc, TRUE, pAcl, FALSE);
    if (!fRet) {
        goto exit;
    }

    // Initialize COM. You may need to modify the parameters of CoInitializeSecurity() for your application.
    // Note that an explicit security descriptor is being passed down.

    hrRet = ::CoInitializeSecurity(&securityDesc,
                                   -1,
                                   NULL,
                                   NULL,
                                   RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                   RPC_C_IMP_LEVEL_IDENTIFY,
                                   NULL,
                                   EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL,
                                   NULL);
    if (FAILED(hrRet)) {
        fRet = FALSE;
        goto exit;
    }

    fRet = TRUE;

exit:

    ::LocalFree(pAcl);

    return fRet;
}


extern "C" 
__declspec(dllexport)
int __cdecl CreateRestorePoint(int argc, WCHAR * *argv)
//示例 1：创建还原点。
{
    RESTOREPOINTINFOW RestorePtInfo;
    STATEMGRSTATUS SMgrStatus;
    PFN_SETRESTOREPTW fnSRSetRestorePointW = NULL;
    DWORD dwErr = ERROR_SUCCESS;
    HMODULE hSrClient = NULL;
    BOOL fRet = FALSE;
    HRESULT hr = S_OK;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"Unexpected error: CoInitializeEx() failed with 0x%08x\n", hr);
        goto exit;
    }

    // Initialize COM security to enable NetworkService,
    // LocalService and System to make callbacks to the process calling  System Restore. 
    // This is required for any process that calls SRSetRestorePoint.

    fRet = InitializeCOMSecurity();
    if (!fRet) {
        wprintf(L"Unexpected error: failed to initialize COM security\n");
        goto exit;
    }

    // Initialize the RESTOREPOINTINFO structure
    RestorePtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;

    // Notify the system that changes are about to be made.
    // An application is to be installed.
    RestorePtInfo.dwRestorePtType = APPLICATION_INSTALL;

    // RestPtInfo.llSequenceNumber must be 0 when creating a restore point.
    RestorePtInfo.llSequenceNumber = 0;

    // String to be displayed by System Restore for this restore point.
    StringCbCopyW(RestorePtInfo.szDescription, sizeof(RestorePtInfo.szDescription), L"First Restore Point");

    // Load the DLL, which may not exist on Windows server
    hSrClient = LoadLibraryW(L"srclient.dll");
    if (NULL == hSrClient) {
        wprintf(L"System Restore is not present.\n");
        goto exit;
    }

    // If the library is loaded, find the entry point
    fnSRSetRestorePointW = (PFN_SETRESTOREPTW)GetProcAddress(hSrClient, "SRSetRestorePointW");
    if (NULL == fnSRSetRestorePointW) {
        wprintf(L"Failed to find SRSetRestorePointW.\n");
        goto exit;
    }

    fRet = fnSRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
    if (!fRet) {
        dwErr = SMgrStatus.nStatus;
        if (dwErr == ERROR_SERVICE_DISABLED) {
            wprintf(L"System Restore is turned off.\n");
            goto exit;
        }
        wprintf(L"Failure to create the restore point; error=%u.\n", dwErr);
        goto exit;
    }

    wprintf(L"Restore point created; number=%I64d.\n", SMgrStatus.llSequenceNumber);

    // The application performs some installation operations here.

    // It is not necessary to call SrSetRestorePoint to indicate that the 
    // installation is complete except in the case of ending a nested restore point. 
    // Every BEGIN_NESTED_SYSTEM_CHANGE must have a 
    // corresponding END_NESTED_SYSTEM_CHANGE or the application cannot create new restore points.

    // Update the RESTOREPOINTINFO structure to notify the system that the operation is finished.
    RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;

    // End the system change by using the sequence number received from the first call to SRSetRestorePoint.
    RestorePtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

    // Notify the system that the operation is done and that this is the end of the restore point.
    fRet = fnSRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
    if (!fRet) {
        dwErr = SMgrStatus.nStatus;
        wprintf(L"Failure to end the restore point; error=%u.\n", dwErr);
        goto exit;
    }

    /*
    创建成功了，但是：
    1.在系统还原列表中是看不到的，只能看到手动创建的。
    2.vssadmin list shadows里也没显示。
    3.WMI的InstancesOf里也没有。    
    */

exit:

    if (hSrClient != NULL) {
        FreeLibrary(hSrClient);
        hSrClient = NULL;
    }

    return 0;
}


extern "C"
__declspec(dllexport)
int __cdecl CreateAndDeleteRestorePoint(int argc, WCHAR * *argv)
//示例 2：创建和取消还原点。
{
    RESTOREPOINTINFOW RestorePtInfo;
    STATEMGRSTATUS SMgrStatus;
    PFN_SETRESTOREPTW fnSRSetRestorePointW = NULL;
    DWORD dwErr = ERROR_SUCCESS;
    HMODULE hSrClient = NULL;
    BOOL fRet = FALSE;
    HRESULT hr = S_OK;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"Unexpected error: CoInitializeEx() failed with 0x%08x\n", hr);
        goto exit;
    }

    // Initialize COM security to enable NetworkService,
    // LocalService and System to make callbacks to the process calling  System Restore. 
    // This is required for any process that calls SRSetRestorePoint.

    fRet = InitializeCOMSecurity();
    if (!fRet) {
        wprintf(L"Unexpected error: failed to initialize COM security\n");
        goto exit;
    }

    // Initialize the RESTOREPOINTINFO structure.
    RestorePtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
    RestorePtInfo.dwRestorePtType = APPLICATION_INSTALL;
    RestorePtInfo.llSequenceNumber = 0;
    StringCbCopyW(RestorePtInfo.szDescription, sizeof(RestorePtInfo.szDescription), L"Sample Restore Point");

    // Load the DLL, which may not exist on Windows server
    hSrClient = LoadLibraryW(L"srclient.dll");
    if (NULL == hSrClient) {
        wprintf(L"System Restore is not present.\n");
        goto exit;
    }

    // If the library is loaded, find the entry point
    fnSRSetRestorePointW = (PFN_SETRESTOREPTW)GetProcAddress(hSrClient, "SRSetRestorePointW");
    if (NULL == fnSRSetRestorePointW) {
        wprintf(L"Failed to find SRSetRestorePointW.\n");
        goto exit;
    }

    fRet = fnSRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
    if (!fRet) {
        dwErr = SMgrStatus.nStatus;
        if (dwErr == ERROR_SERVICE_DISABLED) {
            wprintf(L"System Restore is turned off.\n");
            goto exit;
        }
        wprintf(L"Failure to create the restore point; error=%u.\n", dwErr);
        goto exit;
    }

    wprintf(L"Restore point set. Restore point data:\n");
    wprintf(L"\tSequence Number=%I64d\n", SMgrStatus.llSequenceNumber);
    wprintf(L"\tStatus=%u\n", SMgrStatus.nStatus);

    // Update the structure to cancel the previous restore point.
    RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;
    RestorePtInfo.dwRestorePtType = CANCELLED_OPERATION;
    // This is the sequence number returned by the previous call.
    RestorePtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

    // Cancel the previous restore point
    fRet = fnSRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
    if (!fRet) {
        dwErr = SMgrStatus.nStatus;
        wprintf(L"Failure to cancel the restore point; error=%u.\n", dwErr);
        goto exit;
    }

    wprintf(L"Restore point canceled. Restore point data:\n");
    wprintf(L"\tSequence Number=%I64d\n", SMgrStatus.llSequenceNumber);
    wprintf(L"\tStatus=%u\n", SMgrStatus.nStatus);

exit:

    if (hSrClient != NULL) {
        FreeLibrary(hSrClient);
        hSrClient = NULL;
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
功能：演示EnumSystemFirmwareTables和GetSystemFirmwareTable的用法。

驱动中对应的函数是
AuxKlibGetSystemFirmwareTable
AuxKlibEnumerateSystemFirmwareTables
AuxKlibInitialize

ExGetFirmwareEnvironmentVariable is the kernel-mode equivalent of the Win32 GetFirmwareEnvironmentVariable function.
ExSetFirmwareEnvironmentVariable is the kernel-mode equivalent of the Win32 SetFirmwareEnvironmentVariable function.

made by correy
made at 2017.06.10
http://correy.webs.com
*/


void get1(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID)
{
    UINT BufferSize = GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, NULL, 0);

    PVOID pFirmwareTableBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);
    _ASSERTE(pFirmwareTableBuffer);

    UINT x = GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    _ASSERTE(x == BufferSize);

    PDESCRIPTION_HEADER p = (PDESCRIPTION_HEADER)pFirmwareTableBuffer;
    _ASSERTE(x == p->Length);

    char buffer[MAX_PATH] = {0};

    RtlCopyMemory(buffer, (const void *)&p->Signature, sizeof(ULONG));
    printf("%s\r\n", buffer);

    RtlZeroMemory(buffer, MAX_PATH);
    RtlCopyMemory(buffer, (const void *)&p->OEMID, ACPI_MAX_OEM_ID);
    printf("%s\r\n", buffer);

    RtlZeroMemory(buffer, MAX_PATH);
    RtlCopyMemory(buffer, (const void *)&p->OEMTableID, ACPI_MAX_TABLE_ID);
    printf("%s\r\n", buffer);

    RtlZeroMemory(buffer, MAX_PATH);
    RtlCopyMemory(buffer, (const void *)&p->CreatorID, ACPI_MAX_CREATOR_ID);
    printf("%s\r\n", buffer);

    printf("\r\n");

    HeapFree(GetProcessHeap(), 0, pFirmwareTableBuffer);
}


void test1(DWORD FirmwareTableProviderSignature)
{
    UINT BufferSize = EnumSystemFirmwareTables(FirmwareTableProviderSignature, NULL, 0);

    PVOID pFirmwareTableBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);
    _ASSERTE(pFirmwareTableBuffer);

    UINT x = EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);

    /*
    The ACPI table provider ('ACPI') returns a list of DWORD table identifiers.
    Each identifier returned corresponds to Signature field of the DESCRIPTION_HEADER structure for an ACPI table currently in the ACPI namespace of the system.
    */

    int * p = (int *)pFirmwareTableBuffer;

    if (FirmwareTableProviderSignature == 'ACPI') {
        int i = 0;
        int n = x / 4;

        for (; i < n; i++) {
            get1(FirmwareTableProviderSignature, p[i]);
        }
    }

    HeapFree(GetProcessHeap(), 0, pFirmwareTableBuffer);
}


void get2(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID)
{
    UINT BufferSize = GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, NULL, 0);

    PVOID pFirmwareTableBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);
    _ASSERTE(pFirmwareTableBuffer);

    UINT x = GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    _ASSERTE(x == BufferSize);

    //这个是啥结构呢？
    //有的说是RawSMBIOSData，我看不是。

    //RawSMBIOSData * p = (RawSMBIOSData *)pFirmwareTableBuffer;
    //_ASSERTE(x == p->Length);

    //char buffer[MAX_PATH] = { 0 };

    //RtlCopyMemory(buffer, (const void *)&p->Signature, sizeof(ULONG));
    //printf("%s\r\n", buffer);

    //RtlZeroMemory(buffer, MAX_PATH);
    //RtlCopyMemory(buffer, (const void *)&p->OEMID, ACPI_MAX_OEM_ID);
    //printf("%s\r\n", buffer);

    //printf("\r\n");

    HeapFree(GetProcessHeap(), 0, pFirmwareTableBuffer);
}


void test2(DWORD FirmwareTableProviderSignature)
{
    UINT BufferSize = EnumSystemFirmwareTables(FirmwareTableProviderSignature, NULL, 0);

    PVOID pFirmwareTableBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);
    _ASSERTE(pFirmwareTableBuffer);

    UINT x = EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);

    /*
    The raw firmware table provider ('FIRM') returns a list of DWORD table identifiers.
    Each identifier corresponds to the beginning of a physical address range.
    Currently, this provider returns 'C0000' and 'E0000'.
    These values correspond to physical memory from 0xC0000 to 0xDFFFF and 0xE0000 to 0xFFFFF, respectively.
    */

    int * p = (int *)pFirmwareTableBuffer;

    if (FirmwareTableProviderSignature == 'FIRM') {
        int i = 0;
        int n = x / 4;

        for (; i < n; i++) {
            get2(FirmwareTableProviderSignature, p[i]);
        }
    }

    HeapFree(GetProcessHeap(), 0, pFirmwareTableBuffer);
}


void get3(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID)
{
    UINT BufferSize = GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, NULL, 0);

    PVOID pFirmwareTableBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);
    _ASSERTE(pFirmwareTableBuffer);

    UINT x = GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    _ASSERTE(x == BufferSize);

    RawSMBIOSData * p = (RawSMBIOSData *)pFirmwareTableBuffer;
    DBG_UNREFERENCED_LOCAL_VARIABLE(p);

    /*
    接下来就解析RawSMBIOSData吧！特别是SMBIOSTableData，这又是一个神秘的未知的结构，有的说是：
    struct SMBios_Thunk
    {
    BYTE flag;
    BYTE data_offset;
    };
    是这样能定位到遗传字符，
    可是这个结构很大，所以，接下来的请继续。
    */

    //char buffer[MAX_PATH] = { 0 };

    //RtlCopyMemory(buffer, (const void *)&p->Signature, sizeof(ULONG));
    //printf("%s\r\n", buffer);

    //RtlZeroMemory(buffer, MAX_PATH);
    //RtlCopyMemory(buffer, (const void *)&p->OEMID, ACPI_MAX_OEM_ID);
    //printf("%s\r\n", buffer);

    //printf("\r\n");

    HeapFree(GetProcessHeap(), 0, pFirmwareTableBuffer);
}


void test3(DWORD FirmwareTableProviderSignature)
{
    UINT BufferSize = EnumSystemFirmwareTables(FirmwareTableProviderSignature, NULL, 0);

    PVOID pFirmwareTableBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);
    _ASSERTE(pFirmwareTableBuffer);

    UINT x = EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);

    //The raw SMBIOS table provider ('RSMB') currently returns a single table identifier, 0x0000. 
    //This corresponds to the raw SMBIOS firmware table.

    int * p = (int *)pFirmwareTableBuffer;

    if (FirmwareTableProviderSignature == 'RSMB') {
        int i = 0;
        int n = x / 4;

        for (; i < n; i++) {
            get3(FirmwareTableProviderSignature, p[i]);
        }
    }

    HeapFree(GetProcessHeap(), 0, pFirmwareTableBuffer);
}


void test4()
/*
功能：测试GetFirmwareEnvironmentVariable函数。
      GetFirmwareEnvironmentVariableEx也差不多。

To read a firmware environment variable, the user account that the app is running under must have the SE_SYSTEM_ENVIRONMENT_NAME privilege. 
A Universal Windows app must be run from an administrator account and follow the requirements outlined in Access UEFI firmware variables from a Universal Windows App.

https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariablea
*/
{
    BOOL b = SetCurrentProcessPrivilege(SE_SYSTEM_ENVIRONMENT_NAME, TRUE);

    //摘自：shutdown.exe的SetBootToFirmware函数。
    __int64 pBuffer{};
    DWORD ret = GetFirmwareEnvironmentVariableW(L"OsIndications",
                                                L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
                                                &pBuffer,
                                                sizeof(pBuffer));
    if (!ret) {
        printf("LastError:%d\n", GetLastError()); //ERROR_INVALID_FUNCTION ERROR_PRIVILEGE_NOT_HELD
    }

    //摘自：shutdown.exe的wmain函数。
    SIZE_T ProviderId{};
    ret = GetFirmwareEnvironmentVariableW(L"OsIndicationsSupported",
                                          L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
                                          &ProviderId,
                                          sizeof(ProviderId));
    if (!ret) {
        printf("LastError:%d\n", GetLastError());  
    }

    SIZE_T dwBytes = 0x100000;
    char * tmp = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytes);
    _ASSERTE(tmp);

    //https://github.com/ExtremeGTX/Win32-UEFILibrary/blob/298f06b23975ca3383f4eb83cd1af86115dd29b2/Win32UEFI/uefi/EFIFunctions.cpp#L32
    //https://github.com/erikberglund/AppleNVRAM/blob/master/EFI/8BE4DF61-93CA-11D2-AA0D-00E098032B8C.md
    //https://github.com/veracrypt/VeraCrypt/blob/6e28375060e043e9039bac4d292ecbcc5e94b08d/src/Common/BootEncryption.cpp#L2637
    ret = GetFirmwareEnvironmentVariableW(L"BootOrder",
                                          L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
                                          tmp,
                                          (DWORD)dwBytes);
    if (!ret) {
        printf("LastError:%d\n", GetLastError());
    }

    HeapFree(GetProcessHeap(), 0, tmp);

    b = SetCurrentProcessPrivilege(SE_SYSTEM_ENVIRONMENT_NAME, FALSE);
}


extern "C"
__declspec(dllexport)
void WINAPI TestSystemFirmwareTable(void)
{
    test1('ACPI');
    test2('FIRM');
    test3('RSMB');
    test4();
}


//////////////////////////////////////////////////////////////////////////////////////////////////
