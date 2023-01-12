#include "pch.h"
#include "Folder.h"


#pragma warning(disable:6011)
#pragma warning(disable:6001)
#pragma warning(disable:6031)
#pragma warning(disable:6283)
#pragma warning(disable:6230)
#pragma warning(disable:6216)


//////////////////////////////////////////////////////////////////////////////////////////////////


/****************************** Module Header ******************************\
* Module Name:  CppShellKnownFolders.cpp
* Project:      CppShellKnownFolders
* Copyright (c) Microsoft Corporation.
*
* The Known Folder system provides a way to interact with certain high-profile folders that are present by default in Microsoft Windows.
* It also allows those same interactions with folders installed and registered with the Known Folder system by applications.
* This sample demonstrates those possible interactions as they are provided by the Known Folder APIs.
*
* A. Enumerate and print all known folders. (PrintAllKnownFolders)
*
* B. Print some built-in known folders like FOLDERID_ProgramFiles in three different ways. (PrintSomeDefaultKnownFolders)
*
* C. Extend known folders with custom folders.
*
*   1 Register and create a known folder named "Sample KnownFolder" under the user profile folder: C:\Users\<username>\SampleKnownFolder.
*   The known folder displays the localized name "Sample KnownFolder LocalizedName", and shows a special folder icon. (CreateKnownFolder, RegisterKnownFolder)
*
*   2 Print the known folder. (PrintKnownFolder)
*
*   3 Remove and unregister the known folder.
*   (RemoveKnownFolder, UnregisterKnownFolder)
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/en-us/openness/resources/licenses.aspx#MPL.
* All other rights reserved.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/


#define GUID_SIZE               128


#define IDI_SAMPLEKF_ICON               103
#define IDS_SAMPLEKF_TOOLTIP            1001
#define IDS_SAMPLEKF_LOCALIZEDNAME      1002


void PrintAllKnownFolders()
/*!
* Enumerate and print all known folders.
*/
{
    HRESULT hr;
    PWSTR pszPath = NULL;

    IKnownFolderManager * pkfm = NULL;
    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pkfm));// Create an IKnownFolderManager instance
    if (SUCCEEDED(hr)) {
        KNOWNFOLDERID * rgKFIDs = NULL;
        UINT cKFIDs = 0;
        hr = pkfm->GetFolderIds(&rgKFIDs, &cKFIDs);// Get the IDs of all known folders
        if (SUCCEEDED(hr)) {
            IKnownFolder * pkfCurrent = NULL;
            for (UINT i = 0; i < cKFIDs; ++i)// Enumerate the known folders. rgKFIDs[i] has the KNOWNFOLDERID
            {
                hr = pkfm->GetFolder(rgKFIDs[i], &pkfCurrent);
                if (SUCCEEDED(hr)) {
                    KNOWNFOLDER_DEFINITION kfd;
                    hr = pkfCurrent->GetFolderDefinition(&kfd);// Get the non-localized, canonical name for the known folder from KNOWNFOLDER_DEFINITION
                    if (SUCCEEDED(hr)) {
                        hr = pkfCurrent->GetPath(0, &pszPath);// Next, get the path of the known folder
                        if (SUCCEEDED(hr)) {
                            wprintf(L"%s: %s\n", kfd.pszName, pszPath);
                            CoTaskMemFree(pszPath);
                        }
                        FreeKnownFolderDefinitionFields(&kfd);
                    }
                    pkfCurrent->Release();
                }
            }
            CoTaskMemFree(rgKFIDs);
        }
        pkfm->Release();
    }
}


void PrintSomeDefaultKnownFolders()
/*!
* Print some default known folders in Windows.
*/
{
    HRESULT hr;
    PWSTR pszPath = NULL;

    // Print the "ProgramFiles" known folder in three ways.

    // Method 1: SHGetKnownFolderPath (The function is new in Windows Vista)
    hr = SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"FOLDERID_ProgramFiles: %s\n", pszPath);

        // The calling application is responsible for calling CoTaskMemFree to free this resource after use.
        CoTaskMemFree(pszPath);
    }

    // Method 2: IKnownFolderManager::GetGetFolder, IKnownFolder::GetPath 
    // (The functions are new in Windows Vista)
    IKnownFolderManager * pkfm = NULL;
    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pkfm));
    if (SUCCEEDED(hr)) {
        IKnownFolder * pkf = NULL;
        hr = pkfm->GetFolder(FOLDERID_ProgramFiles, &pkf);
        if (SUCCEEDED(hr)) {
            hr = pkf->GetPath(0, &pszPath);
            if (SUCCEEDED(hr)) {
                wprintf(L"FOLDERID_ProgramFiles: %s\n", pszPath);

                // The calling application is responsible for calling 
                // CoTaskMemFree to free this resource after use.
                CoTaskMemFree(pszPath);
            }
            pkf->Release();
        }
        pkfm->Release();
    }

    // Method 3: SHGetFolderPath (The function is deprecated. As of Windows Vista, this function is merely a wrapper for SHGetKnownFolderPath.)
    TCHAR szFolderPath[MAX_PATH];
    hr = SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, szFolderPath);
    if (SUCCEEDED(hr)) {
        _tprintf(_T("FOLDERID_ProgramFiles: %s\n"), szFolderPath);
    }

    // Print known folders for per-computer program data.

    // The user would never want to browse here in Explorer, and settings 
    // changed here should affect every user on the machine. The default 
    // location is %systemdrive%\ProgramData, which is a hidden folder, on an 
    // installation of Windows Vista. You'll want to create your directory 
    // and set the ACLs you need at install time.
    hr = SHGetKnownFolderPath(FOLDERID_ProgramData, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"FOLDERID_ProgramData: %s\n", pszPath);
        CoTaskMemFree(pszPath);
    }

    // The user would want to browse here in Explorer and double click to open the file. 
    // The default location is %public%, which has explicit links throughout Explorer, on an installation of Windows Vista. 
    // You'll want to create your directory and set the ACLs you need at install time.
    hr = SHGetKnownFolderPath(FOLDERID_Public, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"FOLDERID_Public: %s\n", pszPath);
        CoTaskMemFree(pszPath);
    }

    // Print known folders for per-user program data.

    // The user would never want to browse here in Explorer, and settings changed here should roam with the user. 
    // The default location is %appdata%, which is a hidden folder, on an installation of Windows Vista.
    hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"FOLDERID_RoamingAppData: %s\n", pszPath);
        CoTaskMemFree(pszPath);
    }

    // The user would never want to browse here in Explorer, and settings changed here should stay local to the computer. 
    // The default location is %localappdata%, which is a hidden folder, on an installation of Windows Vista.
    hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"FOLDERID_LocalAppData: %s\n", pszPath);
        CoTaskMemFree(pszPath);
    }

    // The user would want to browse here in Explorer and double click to open the file. 
    // The default location is %userprofile%\documents, which has explicit links throughout Explorer, on an installation of Windows Vista.
    hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"FOLDERID_Documents: %s\n", pszPath);
        CoTaskMemFree(pszPath);
    }
}


#pragma region Extending Known Folders with Custom Folders


HRESULT CreateKnownFolder(REFKNOWNFOLDERID kfid);
HRESULT RegisterKnownFolder(REFKNOWNFOLDERID kfid);
HRESULT RemoveKnownFolder(REFKNOWNFOLDERID kfid);
HRESULT UnregisterKnownFolder(REFKNOWNFOLDERID kfid);
void PrintKnownFolder(REFKNOWNFOLDERID kfid);


HRESULT CreateKnownFolder(REFKNOWNFOLDERID kfid)
/*!
* Register and create a known folder named "Sample KnownFolder" under the
* user profile folder: C:\Users\<username>\SampleKnownFolder. The known
* folder displays the localized name "Sample KnownFolder LocalizedName", and
* shows a special folder icon.
*
* CreateKnownFolder calls RegisterKnownFolder to register a known folder. In
* RegisterKnownFolder, first define the known folder through a
* KNOWNFOLDER_DEFINITION structure. You can specify the known folder's
* canonical name, localized name, tooltip, folder icon, etc. Then register
* the known folder through a call to IKnownFolderManager::RegisterFolder.
* IKnownFolderManager::RegisterFolder requires that the current process is
* run as administrator to succeed.
*
* After the known folder is register, CreateKnownFolder initializes and
* creates the folder with SHGetKnownFolderPath with the flags KF_FLAG_CREATE | KF_FLAG_INIT so that the Shell will write desktop.ini in the folder.
* This is how our customizations (i.e. pszIcon, pszTooltip, pszLocalizedName) get picked up by the Shell.
* If SHGetKnownFolderPath fails, the function UnregisterKnownFolder is invoked to undo the registration.
*/
{
    HRESULT hr = RegisterKnownFolder(kfid);// Register the known folder
    if (SUCCEEDED(hr)) {
        // Create the known folder with SHGetKnownFolderPath with the flags KF_FLAG_CREATE | KF_FLAG_INIT so that the Shell will write desktop.ini in the folder. 
        // This is how our customizations (i.e. pszIcon, pszTooltip, pszLocalizedName) get picked up by the Shell.
        PWSTR pszPath = NULL;
        hr = SHGetKnownFolderPath(kfid, KF_FLAG_CREATE | KF_FLAG_INIT, NULL, &pszPath);
        if (FAILED(hr)) {
            _tprintf(_T("SHGetKnownFolderPath failed w/err 0x%08lx\n"), hr);// Failed to initialize and create the known folder			
            UnregisterKnownFolder(kfid);// Unregister the known folder because of the failure
        } else {
            wprintf(L"The known folder is registered and created:\n%s\n", pszPath);
            CoTaskMemFree(pszPath);// Must free the pszPath output of SHGetKnownFolderPath
        }
    }

    return hr;
}


HRESULT RegisterKnownFolder(REFKNOWNFOLDERID kfid)
/*!
* Register a known folder.
The function requires administrative privilege, so please make sure that the routine is run as administrator.
*/
{
    HRESULT hr;

    // Define your known folder through a KNOWNFOLDER_DEFINITION structure.

    KNOWNFOLDER_DEFINITION kfd = {};
    kfd.category = KF_CATEGORY_PERUSER;
    kfd.pszName = (LPWSTR)L"Sample KnownFolder";	// Known folder canonical name
    kfd.pszDescription = (LPWSTR)L"This is a sample known folder";

    // fidParent and pszRelativePath work together. pszRelativePath specifies a path relative to the parent folder specified in fidParent.
    kfd.fidParent = FOLDERID_Profile;
    kfd.pszRelativePath = (LPWSTR)L"SampleKnownFolder";

    // pszParsingName points to Shell namespace folder path of the folder, stored as a null-terminated Unicode string. Applies to virtual folders only. 
    // For example, ::%CLSID_MyComputer%\::%CLSID_ControlPanel% is the parsing name of Control Panel.
    GUID guid;
    CoCreateGuid(&guid);
    kfd.pszParsingName = (PWSTR)CoTaskMemAlloc(sizeof(WCHAR) * GUID_SIZE);
    if (kfd.pszParsingName) {
        StringFromGUID2(guid, kfd.pszParsingName, GUID_SIZE);
    }

    // Get the current exe module path for the pszTooltip, pszLocalizedName, and pszIcon fields.
    WCHAR szExePath[MAX_PATH] = {};
    GetModuleFileName(NULL, szExePath, ARRAYSIZE(szExePath));
    size_t cch = ARRAYSIZE(szExePath) + 10;	// +10 as a flexible buffer

    // pszTooltip points to the default tool tip resource used for this known folder when it is created. 
    // This is a null-terminated Unicode string in this form: @Module name, Resource ID Here we use the current exe module to store the string resource.
    kfd.pszTooltip = (PWSTR)CoTaskMemAlloc(sizeof(WCHAR) * cch);
    if (kfd.pszTooltip) {
        ZeroMemory(kfd.pszTooltip, sizeof(WCHAR) * cch);
        StringCchPrintfW(kfd.pszTooltip, cch, L"@%s,-%d", szExePath, IDS_SAMPLEKF_TOOLTIP);
    }

    // pszLocalizedName points to the default localized name resource used when the folder is created. 
    // This is a null-terminated Unicode string in this form: @Module name, Resource ID Here we use the current exe module to store the string resource.
    kfd.pszLocalizedName = (PWSTR)CoTaskMemAlloc(sizeof(WCHAR) * cch);
    if (kfd.pszLocalizedName) {
        ZeroMemory(kfd.pszLocalizedName, sizeof(WCHAR) * cch);
        StringCchPrintfW(kfd.pszLocalizedName, cch, L"@%s,-%d", szExePath, IDS_SAMPLEKF_LOCALIZEDNAME);
    }

    // pszIcon points to the default icon resource used when the folder is created. 
    // This is a null-terminated Unicode string in this form: 
    // Module name, Resource ID
    // Here we use the current exe module to store the icon resource.
    kfd.pszIcon = (PWSTR)CoTaskMemAlloc(sizeof(WCHAR) * cch);
    if (kfd.pszIcon) {
        ZeroMemory(kfd.pszIcon, sizeof(WCHAR) * cch);
        StringCchPrintfW(kfd.pszIcon, cch, L"%s,-%d", szExePath, IDI_SAMPLEKF_ICON);
    }

    // Register the known folder through a call to RegisterFolder.

    // Create IKnownFolderManager instance
    IKnownFolderManager * pkfm = NULL;
    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pkfm));
    if (SUCCEEDED(hr)) {
        hr = pkfm->RegisterFolder(kfid, &kfd);
        if (FAILED(hr)) {
            _tprintf(_T("IKnownFolderManager::RegisterFolder failed w/err ") \
                     _T("0x%08lx\nPlease run as admin to register a known folder\n"),
                     hr);
        }
        pkfm->Release();
    }

    return hr;
}


HRESULT RemoveKnownFolder(REFKNOWNFOLDERID kfid)
/*!
* Remove and unregister a known folder.
*
* RemoveKnownFolder is responsible for remove and unregister the specified known folder.
* It first gets the physical folder path of the known folder, and attempts to delete it.
* When the deletion succeeds, the function calls UnregisterKnownFolder to unregister the known folder from registry.
* UnregisterKnownFolder requires administrator privilege, so please make sure that the routine is run as administrator.
*/
{
    // Get the physical folder of the known folder.
    PWSTR pszPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(kfid, 0, NULL, &pszPath);
    if (FAILED(hr)) {
        // Failed to get the physical folder of the known folder.
        _tprintf(_T("SHGetKnownFolderPath failed w/err 0x%08lx\n"), hr);
    } else {
        int _tempLen = (2 * (int)wcslen(pszPath) + 1);
        PWSTR _tempMemory = new WCHAR[_tempLen];
        for (int i = 0; i < _tempLen; i++) {
            _tempMemory[i] = 0;
        }

        memcpy(_tempMemory, pszPath, 2 * (wcslen(pszPath)));

        // Attempt to remove the physical folder of the known folder.
        SHFILEOPSTRUCT fos = {};
        fos.wFunc = FO_DELETE;
        fos.pFrom = _tempMemory;
        fos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        int err = SHFileOperation(&fos);
        if (0 != err) {
            // Failed to remove the physical folder
            _tprintf(_T("SHFileOperation failed w/err 0x%08lx\n"), err);
            hr = E_FAIL;
        } else {
            // If the physical folder was deleted successfully, attempt to unregister the known folder.
            hr = UnregisterKnownFolder(kfid);
            if (SUCCEEDED(hr)) {
                wprintf(L"The known folder is unregistered and removed:\n%s\n", pszPath);
            }
        }

        // Must free the pszPath output of SHGetKnownFolderPath
        CoTaskMemFree(pszPath);
        delete(_tempMemory);
    }

    return hr;
}


HRESULT UnregisterKnownFolder(REFKNOWNFOLDERID kfid)
/*!
* Unregister a known folder.
The function requires administrator privilege, so please make sure that the routine is run as administrator.
*/
{
    IKnownFolderManager * pkfm = NULL;
    HRESULT hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pkfm));
    if (SUCCEEDED(hr)) {
        hr = pkfm->UnregisterFolder(kfid);
        if (FAILED(hr)) {
            _tprintf(_T("IKnownFolderManager::UnregisterFolder failed w/err") \
                     _T(" 0x%08lx\n"), hr);
        }
        pkfm->Release();
    }

    return hr;
}


void PrintKnownFolder(REFKNOWNFOLDERID kfid)
/*!
* Print a known folder.
*/
{
    PWSTR pszPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(kfid, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        wprintf(L"The known folder is: %s\n", pszPath);

        // The calling application is responsible for calling CoTaskMemFree to free this resource after use.
        CoTaskMemFree(pszPath);
    } else {
        // Failed to get the physical folder of the known folder.
        _tprintf(_T("SHGetKnownFolderPath failed w/err 0x%08lx\n"), hr);
    }
}


#pragma endregion


EXTERN_C
__declspec(dllexport)
int WINAPI CppShellKnownFolders(int argc, _TCHAR * argv[])
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);// Initialize COM

    _putts(_T("Print all known folders"));
    PrintAllKnownFolders();// Enumerate and print all known folders

    // Print some default known folders
    _putts(_T("\nPrint some default known folder"));
    PrintSomeDefaultKnownFolders();

#pragma region Extending Known Folders with Custom Folders    	
    KNOWNFOLDERID kfid = GUID_NULL;
    CoCreateGuid(&kfid);// Create an ID for the known folder

    _putts(_T("\nRegister and create a known folder"));
    CreateKnownFolder(kfid);// Register and create a known folder
    //getchar();	// Check for the known folder

    // Print the registered known folder
    _putts(_T("\nPrint the known folder"));
    PrintKnownFolder(kfid);

    // Remove and unregister the known folder
    _putts(_T("\nRemove and unregister the known folder"));
    RemoveKnownFolder(kfid);
#pragma endregion

    CoUninitialize();
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI GetImageFilePath(_Out_ LPWSTR ImageFilePath, _In_ DWORD nSize)
/*
功能：获取进程所在的目录。

此目录区别于GetCurrentDirectory.
*/
{
    GetModuleFileName(NULL, ImageFilePath, nSize);

    ImageFilePath[lstrlen(ImageFilePath) - lstrlen(PathFindFileName(ImageFilePath))] = 0;

    PathRemoveBackslash(ImageFilePath);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void GetFolderPath()
/*
只能运行在服务中。
*/
{
    DWORD dwActiveSessionId = WTSGetActiveConsoleSessionId();
    HANDLE hUserToken = INVALID_HANDLE_VALUE;

    BOOL bSuccess = WTSQueryUserToken(dwActiveSessionId, &hUserToken);
    if (bSuccess) {
        bSuccess = ImpersonateLoggedOnUser(hUserToken);
        if (bSuccess) {
            TCHAR szPath[MAX_PATH];
            if (S_OK == SHGetFolderPath(NULL, CSIDL_APPDATA, hUserToken, SHGFP_TYPE_DEFAULT, szPath)) {

            }

            CloseHandle(hUserToken);
            RevertToSelf();
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int EnumDesktopFolder()
/*
文件名:IShellFolder.Cpp
功能:列出桌面的所以的(子)文件和(子)文件夹.

至今方知目录和文件夹的区别.
Windows Shell一直是一个知道但不熟悉的名字.

Windows Shell搞懂了,再搞COM等.

参考示例:
http://msdn.microsoft.com/en-us/library/windows/desktop/bb776885(v=vs.85).aspx
http://msdn.microsoft.com/en-us/library/windows/desktop/bb776889(v=vs.85).aspx

made by correy
made at 2013.11.18
*/
{
    IShellFolder * psfDeskTop = NULL;
    HRESULT hr = SHGetDesktopFolder(&psfDeskTop);//获取对象的地址.

    LPENUMIDLIST ppenum = NULL;
    hr = psfDeskTop->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS, &ppenum);//获取对象的地址.

    ULONG celtFetched;
    LPITEMIDLIST pidlItems = NULL;
    while (hr = ppenum->Next(1, &pidlItems, &celtFetched) == S_OK && (celtFetched) == 1) //获取pidlItems
    {
        STRRET strDispName;
        psfDeskTop->GetDisplayNameOf(pidlItems, SHGDN_INFOLDER, &strDispName);//获取strDispName

        printf("%ls\n", strDispName.pOleStr);

        CoTaskMemFree(pidlItems);
    }

    ppenum->Release();

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
bool WINAPI DelDirByApi(_In_ LPCWSTR Dir)
{
    // Check that the input path plus 3 is not longer than MAX_PATH.
    // Three characters are for the "\*" plus NULL appended below.
    size_t length_of_arg;
    StringCchLength(Dir, MAX_PATH, &length_of_arg);//argv[1]
    if (length_of_arg > (MAX_PATH - 3)) {
        _tprintf(TEXT("\nDirectory path is too long.\n"));
        return false;
    }

    // Prepare string for use with FindFile functions.  
    // First, copy the string to a buffer, then append '\*' to the directory name.
    TCHAR szDir[MAX_PATH];
    StringCchCopy(szDir, MAX_PATH, Dir);//argv[1]
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

    // Find the first file in the directory.
    WIN32_FIND_DATA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    hFind = FindFirstFile(szDir, &ffd);
    if (INVALID_HANDLE_VALUE == hFind) {
        DisplayErrorBox(TEXT("FindFirstFile"));
        return false;
    }

    // List all the files in the directory with some info about them.
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            //_tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName);
            if (lstrcmpi(ffd.cFileName, L".") == 0 ||
                lstrcmpi(ffd.cFileName, L"..") == 0) {
                //这里不操作。
            } else {
                TCHAR sztemp[MAX_PATH] = {0};
                StringCchCopy(sztemp, MAX_PATH, Dir);//argv[1]
                PathAppend(sztemp, ffd.cFileName);
                DelDirByApi(sztemp);

                /*_tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName);*/
            }
        } else {
            //LARGE_INTEGER filesize;//这几行显示信息用的，无实际用途。
            //filesize.LowPart = ffd.nFileSizeLow;
            //filesize.HighPart = ffd.nFileSizeHigh;
            //_tprintf(TEXT("  %s   %ld bytes\n"), ffd.cFileName, filesize.QuadPart);

            TCHAR sztemp[MAX_PATH] = {0};
            StringCchCopy(sztemp, MAX_PATH, Dir);//argv[1]
            PathAppend(sztemp, ffd.cFileName);
            bool b = DeleteFile(sztemp);
            if (b == 0) {
                _tprintf(TEXT("LastError:%d.\n"), GetLastError());
            }
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    //dwError = GetLastError();
    //if (dwError != ERROR_NO_MORE_FILES) {
    //    DisplayErrorBox(TEXT("FindFirstFile"));
    //}

    FindClose(hFind);

    return RemoveDirectory(Dir);//里面有空文件夹依旧任务是空目录。返回0失败。
}


EXTERN_C
__declspec(dllexport)
void WINAPI DelDirByShell(_In_ LPCWSTR Dir)
{
    if (!PathFileExists(Dir)) {
        return;
    }

    TCHAR DelDir[MAX_PATH] = {0};
    lstrcpy(DelDir, Dir);
    int len = lstrlen(Dir);
    DelDir[len] = 0;
    DelDir[len + 1] = 0;

    SHFILEOPSTRUCT FileOp;
    ZeroMemory((void *)&FileOp, sizeof(SHFILEOPSTRUCT));

    FileOp.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    FileOp.hNameMappings = NULL;
    FileOp.hwnd = NULL;
    FileOp.lpszProgressTitle = NULL;
    FileOp.pFrom = DelDir;
    FileOp.pTo = NULL;
    FileOp.wFunc = FO_DELETE;

    int err = SHFileOperation(&FileOp);
    if (0 != err) {
        //失败。
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
;获取某些目录的路径。
;SHGetFolderPath好像被SHGetKnownFolderPath和SHGetSpecialFolderPath替代。
;CSIDL好像又被KNOWNFOLDERID代替。
;本文以SHGetSpecialFolderPath为例写代码。
.386
.model flat,stdcall
option casemap:none

include windows.inc
;include winextra.inc

include kernel32.inc
includelib kernel32.lib

include shell32.inc
includelib shell32.lib

CSIDL_ADMINTOOLS                 equ 0030h
CSIDL_ALTSTARTUP                 equ 001dh
CSIDL_APPDATA                    equ 001ah
CSIDL_BITBUCKET                  equ 000ah
CSIDL_CDBURN_AREA                equ 003bh
CSIDL_COMMON_ADMINTOOLS          equ 002fh
CSIDL_COMMON_ALTSTARTUP          equ 001eh
CSIDL_COMMON_APPDATA             equ 0023h
CSIDL_COMMON_DESKTOPDIRECTORY    equ 0019h
CSIDL_COMMON_DOCUMENTS           equ 002eh
CSIDL_COMMON_FAVORITES           equ 001fh
CSIDL_COMMON_MUSIC               equ 0035h
CSIDL_COMMON_OEM_LINKS           equ 003ah
CSIDL_COMMON_PICTURES            equ 0036h
CSIDL_COMMON_PROGRAMS            equ 0017h
CSIDL_COMMON_STARTMENU           equ 0016h
CSIDL_COMMON_STARTUP             equ 0018h
CSIDL_COMMON_TEMPLATES           equ 002dh
CSIDL_COMMON_VIDEO               equ 0037h
CSIDL_COMPUTERSNEARME            equ 003dh
CSIDL_CONNECTIONS                equ 0031h
CSIDL_CONTROLS                   equ 0003h
CSIDL_COOKIES                    equ 0021h
CSIDL_DESKTOP                    equ 0000h
CSIDL_DESKTOPDIRECTORY           equ 0010h
CSIDL_DRIVES                     equ 0011h
CSIDL_FAVORITES                  equ 0006h
CSIDL_FLAG_CREATE                equ 8000h
CSIDL_FLAG_DONT_UNEXPAND         equ 2000h
CSIDL_FLAG_DONT_VERIFY           equ 4000h
CSIDL_FLAG_MASK                  equ 0FF00h
CSIDL_FLAG_NO_ALIAS              equ 1000h
CSIDL_FLAG_PER_USER_INIT         equ 0800h
CSIDL_FONTS                      equ 0014h
CSIDL_HISTORY                    equ 0022h
CSIDL_INTERNET                   equ 0001h
CSIDL_INTERNET_CACHE             equ 0020h
CSIDL_LOCAL_APPDATA              equ 001ch
;CSIDL_MYDOCUMENTS                equ 0005h
CSIDL_MYMUSIC                    equ 000dh
CSIDL_MYPICTURES                 equ 0027h
CSIDL_MYVIDEO                    equ 000eh
CSIDL_NETHOOD                    equ 0013h
CSIDL_NETWORK                    equ 0012h
CSIDL_PERSONAL                   equ 0005h
CSIDL_PRINTERS                   equ 0004h
CSIDL_PRINTHOOD                  equ 001bh
CSIDL_PROFILE                    equ 0028h
CSIDL_PROGRAMS                   equ 0002h
CSIDL_PROGRAM_FILES              equ 0026h
CSIDL_PROGRAM_FILESX86           equ 002ah
CSIDL_PROGRAM_FILES_COMMON       equ 002bh
CSIDL_PROGRAM_FILES_COMMONX86    equ 002ch
CSIDL_RECENT                     equ 0008h
CSIDL_RESOURCES                  equ 0038h
CSIDL_RESOURCES_LOCALIZED        equ 0039h
CSIDL_SENDTO                     equ 0009h
CSIDL_STARTMENU                  equ 000bh
CSIDL_STARTUP                    equ 0007h
CSIDL_SYSTEM                     equ 0025h
CSIDL_SYSTEMX86                  equ 0029h
CSIDL_TEMPLATES                  equ 0015h
CSIDL_WINDOWS                    equ 0024h

.data?
buffer db 512 dup (?)
path db 512 dup (?)

.code

hstdout dd 0
hstdin dd 0
x dd 0

szCSIDL_ADMINTOOLS db "FOLDERID_AdminTools:",0
szCSIDL_ALTSTARTUP db "FOLDERID_Startup:",0
szCSIDL_APPDATA db "FOLDERID_RoamingAppData:",0
szCSIDL_BITBUCKET db "FOLDERID_RecycleBinFolder:",0
szCSIDL_CDBURN_AREA db "FOLDERID_CDBurning:",0
szCSIDL_COMMON_ADMINTOOLS db "FOLDERID_CommonAdminTools:",0
szCSIDL_COMMON_ALTSTARTUP db "FOLDERID_CommonStartup:",0
szCSIDL_COMMON_APPDATA db "FOLDERID_ProgramData:",0
szCSIDL_COMMON_DESKTOPDIRECTORY db "FOLDERID_PublicDesktop:",0
szCSIDL_COMMON_DOCUMENTS db "FOLDERID_PublicDocuments:",0
szCSIDL_COMMON_FAVORITES db "FOLDERID_Favorites:",0
szCSIDL_COMMON_MUSIC db "FOLDERID_PublicMusic:",0
szCSIDL_COMMON_OEM_LINKS db "FOLDERID_CommonOEMLinks:",0
szCSIDL_COMMON_PICTURES db "FOLDERID_PublicPictures:",0
szCSIDL_COMMON_PROGRAMS db "FOLDERID_CommonPrograms:",0
szCSIDL_COMMON_STARTMENU db "FOLDERID_CommonStartMenu:",0
szCSIDL_COMMON_STARTUP db "FOLDERID_CommonStartup:",0
szCSIDL_COMMON_TEMPLATES db "FOLDERID_CommonTemplates:",0
szCSIDL_COMMON_VIDEO db "FOLDERID_PublicVideos:",0
szCSIDL_COMPUTERSNEARME db "FOLDERID_NetworkFolder:",0
szCSIDL_CONNECTIONS db "FOLDERID_ConnectionsFolder:",0
szCSIDL_CONTROLS db "FOLDERID_ControlPanelFolder:",0
szCSIDL_COOKIES db "FOLDERID_Cookies:",0
szCSIDL_DESKTOP db "FOLDERID_Desktop:",0
szCSIDL_DESKTOPDIRECTORY db "FOLDERID_Desktop:",0
szCSIDL_DRIVES db "FOLDERID_ComputerFolder:",0
szCSIDL_FAVORITES db "FOLDERID_Favorites:",0
szCSIDL_FONTS db "FOLDERID_Fonts:",0
szCSIDL_HISTORY db "FOLDERID_History:",0
szCSIDL_INTERNET db "FOLDERID_InternetFolder:",0
szCSIDL_INTERNET_CACHE db "FOLDERID_InternetCache:",0
szCSIDL_LOCAL_APPDATA db "FOLDERID_LocalAppData:",0
szCSIDL_MYDOCUMENTS db "FOLDERID_Documents:",0
szCSIDL_MYMUSIC db "FOLDERID_Music:",0
szCSIDL_MYPICTURES db "FOLDERID_Pictures:",0
szCSIDL_MYVIDEO db "FOLDERID_Videos:",0
szCSIDL_NETHOOD db "FOLDERID_NetHood:",0
szCSIDL_NETWORK db "FOLDERID_NetworkFolder:",0
szCSIDL_PERSONAL db "FOLDERID_Documents:",0
szCSIDL_PRINTERS db "FOLDERID_PrintersFolder:",0
szCSIDL_PRINTHOOD db "FOLDERID_PrintHood:",0
szCSIDL_PROFILE db "FOLDERID_Profile:",0
szCSIDL_PROGRAM_FILES db "FOLDERID_ProgramFiles:",0
szCSIDL_PROGRAM_FILESX86 db "FOLDERID_ProgramFilesX86:",0
szCSIDL_PROGRAM_FILES_COMMON db "FOLDERID_ProgramFilesCommon:",0
szCSIDL_PROGRAM_FILES_COMMONX86 db "FOLDERID_ProgramFilesCommonX86:",0
szCSIDL_PROGRAMS db "FOLDERID_Programs:",0
szCSIDL_RECENT db "FOLDERID_Recent:",0
szCSIDL_RESOURCES db "FOLDERID_ResourceDir:",0
szCSIDL_RESOURCES_LOCALIZED db "FOLDERID_LocalizedResourcesDir:",0
szCSIDL_SENDTO db "FOLDERID_SendTo:",0
szCSIDL_STARTMENU db "FOLDERID_StartMenu:",0
szCSIDL_STARTUP db "FOLDERID_Startup:",0
szCSIDL_SYSTEM db "FOLDERID_System:",0
szCSIDL_SYSTEMX86 db "FOLDERID_SystemX86:",0
szCSIDL_TEMPLATES db "FOLDERID_Templates:",0
szCSIDL_WINDOWS db "FOLDERID_Windows:",0

sz_enter db 13,10,0
notice db "按enter键退出！",13,10,0
correy db "made by correy",0
szsysdir db "系统盘",0 ;有极少数的几个没有带盘符，所以加这个。

ShowSpecialFolderPath proc CSIDL,szCSIDL
  invoke RtlZeroMemory,addr buffer,sizeof buffer
  invoke RtlZeroMemory,addr path,sizeof path
  invoke SHGetSpecialFolderPathW,0,addr buffer,CSIDL,0

  invoke lstrlen,szCSIDL
  invoke WriteFile,hstdout,szCSIDL,eax,addr x,0

  invoke lstrlenW,addr buffer+2
  invoke WideCharToMultiByte,0,0,addr buffer+2,eax,addr path,sizeof path,0,0

  invoke WriteFile,hstdout,addr szsysdir,sizeof szsysdir,addr x,0

  invoke lstrlen,addr path
  invoke WriteFile,hstdout,addr path,eax,addr x,0

  invoke WriteFile,hstdout,addr sz_enter,sizeof sz_enter-1,addr x,0
  ret
ShowSpecialFolderPath endp

start:
invoke GetStdHandle,-10
mov hstdin,eax
invoke GetStdHandle,-11
mov hstdout,eax

invoke SetConsoleTitle,addr correy
invoke SetConsoleScreenBufferSize,hstdout,01000099h;高字是高度，低字是宽度。
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
invoke SHGetSpecialFolderPathW,0,addr buffer,CSIDL_ADMINTOOLS,0
invoke WriteFile,hstdout,addr szCSIDL_ADMINTOOLS,sizeof szCSIDL_ADMINTOOLS-1,addr x,0

invoke lstrlenW,addr buffer+2
invoke WideCharToMultiByte,0,0,addr buffer+2,eax,addr path,sizeof path,0,0

invoke WriteFile,hstdout,addr szsysdir,sizeof szsysdir,addr x,0

invoke lstrlen,addr path
invoke WriteFile,hstdout,addr path,eax,addr x,0

invoke WriteFile,hstdout,addr sz_enter,sizeof sz_enter-1,addr x,0
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;本人没有找到CSIDL的规律，如果有我想一个循环应该可以解决。
invoke ShowSpecialFolderPath,CSIDL_ALTSTARTUP,addr szCSIDL_ALTSTARTUP
invoke ShowSpecialFolderPath,CSIDL_APPDATA,addr szCSIDL_APPDATA
invoke ShowSpecialFolderPath,CSIDL_BITBUCKET ,addr szCSIDL_BITBUCKET
invoke ShowSpecialFolderPath,CSIDL_CDBURN_AREA ,addr szCSIDL_CDBURN_AREA
invoke ShowSpecialFolderPath,CSIDL_COMMON_ADMINTOOLS,addr szCSIDL_COMMON_ADMINTOOLS
invoke ShowSpecialFolderPath,CSIDL_COMMON_ALTSTARTUP ,addr szCSIDL_COMMON_ALTSTARTUP
invoke ShowSpecialFolderPath,CSIDL_COMMON_APPDATA,addr szCSIDL_COMMON_APPDATA
invoke ShowSpecialFolderPath,CSIDL_COMMON_DESKTOPDIRECTORY,addr szCSIDL_COMMON_DESKTOPDIRECTORY
invoke ShowSpecialFolderPath,CSIDL_COMMON_DOCUMENTS,addr szCSIDL_COMMON_DOCUMENTS
invoke ShowSpecialFolderPath,CSIDL_COMMON_FAVORITES,addr szCSIDL_COMMON_FAVORITES
invoke ShowSpecialFolderPath,CSIDL_COMMON_MUSIC,addr szCSIDL_COMMON_MUSIC
invoke ShowSpecialFolderPath,CSIDL_COMMON_OEM_LINKS,addr szCSIDL_COMMON_OEM_LINKS
invoke ShowSpecialFolderPath,CSIDL_COMMON_PICTURES,addr szCSIDL_COMMON_PICTURES
invoke ShowSpecialFolderPath,CSIDL_COMMON_PROGRAMS,addr szCSIDL_COMMON_PROGRAMS
invoke ShowSpecialFolderPath,CSIDL_COMMON_STARTMENU,addr szCSIDL_COMMON_STARTMENU
invoke ShowSpecialFolderPath,CSIDL_COMMON_STARTUP,addr szCSIDL_COMMON_STARTUP
invoke ShowSpecialFolderPath,CSIDL_COMMON_TEMPLATES,addr szCSIDL_COMMON_TEMPLATES
invoke ShowSpecialFolderPath,CSIDL_COMMON_VIDEO,addr szCSIDL_COMMON_VIDEO
invoke ShowSpecialFolderPath,CSIDL_COMPUTERSNEARME,addr szCSIDL_COMPUTERSNEARME
invoke ShowSpecialFolderPath,CSIDL_CONNECTIONS,addr szCSIDL_CONNECTIONS
invoke ShowSpecialFolderPath,CSIDL_COOKIES,addr szCSIDL_COOKIES
invoke ShowSpecialFolderPath,CSIDL_DESKTOP,addr szCSIDL_DESKTOP
invoke ShowSpecialFolderPath,CSIDL_DESKTOPDIRECTORY,addr szCSIDL_DESKTOPDIRECTORY
invoke ShowSpecialFolderPath,CSIDL_DRIVES ,addr szCSIDL_DRIVES
invoke ShowSpecialFolderPath,CSIDL_FAVORITES,addr szCSIDL_FAVORITES
invoke ShowSpecialFolderPath,CSIDL_FONTS,addr szCSIDL_FONTS
invoke ShowSpecialFolderPath,CSIDL_HISTORY,addr szCSIDL_HISTORY
invoke ShowSpecialFolderPath,CSIDL_INTERNET,addr szCSIDL_INTERNET
invoke ShowSpecialFolderPath,CSIDL_INTERNET_CACHE,addr szCSIDL_INTERNET_CACHE
invoke ShowSpecialFolderPath,CSIDL_LOCAL_APPDATA ,addr szCSIDL_LOCAL_APPDATA
invoke ShowSpecialFolderPath,5,addr szCSIDL_MYDOCUMENTS ;CSIDL_MYDOCUMENTS
invoke ShowSpecialFolderPath,CSIDL_MYMUSIC,addr szCSIDL_MYMUSIC
invoke ShowSpecialFolderPath,CSIDL_MYPICTURES ,addr szCSIDL_MYPICTURES
invoke ShowSpecialFolderPath,CSIDL_MYMUSIC,addr szCSIDL_MYMUSIC
invoke ShowSpecialFolderPath,CSIDL_MYPICTURES ,addr szCSIDL_MYPICTURES
invoke ShowSpecialFolderPath,CSIDL_MYVIDEO,addr szCSIDL_MYVIDEO
invoke ShowSpecialFolderPath,CSIDL_NETHOOD ,addr szCSIDL_NETHOOD
invoke ShowSpecialFolderPath,CSIDL_NETWORK,addr szCSIDL_NETWORK
invoke ShowSpecialFolderPath,CSIDL_PERSONAL ,addr szCSIDL_PERSONAL
invoke ShowSpecialFolderPath,CSIDL_PRINTERS,addr szCSIDL_PRINTERS
invoke ShowSpecialFolderPath,CSIDL_PRINTHOOD,addr szCSIDL_PRINTHOOD
invoke ShowSpecialFolderPath,CSIDL_PROFILE,addr szCSIDL_PROFILE
invoke ShowSpecialFolderPath,CSIDL_PROGRAM_FILES ,addr szCSIDL_PROGRAM_FILES
invoke ShowSpecialFolderPath,CSIDL_PROGRAM_FILESX86,addr szCSIDL_PROGRAM_FILESX86
invoke ShowSpecialFolderPath,CSIDL_PROGRAM_FILES_COMMON,addr szCSIDL_PROGRAM_FILES_COMMON
invoke ShowSpecialFolderPath,CSIDL_PROGRAM_FILES_COMMONX86,addr szCSIDL_PROGRAM_FILES_COMMONX86
invoke ShowSpecialFolderPath,CSIDL_PROGRAMS,addr szCSIDL_PROGRAMS
invoke ShowSpecialFolderPath,CSIDL_RECENT,addr szCSIDL_RECENT
invoke ShowSpecialFolderPath,CSIDL_RESOURCES,addr szCSIDL_RESOURCES
invoke ShowSpecialFolderPath,CSIDL_RESOURCES_LOCALIZED,addr szCSIDL_RESOURCES_LOCALIZED
invoke ShowSpecialFolderPath,CSIDL_SENDTO,addr szCSIDL_SENDTO
invoke ShowSpecialFolderPath,CSIDL_STARTMENU,addr szCSIDL_STARTMENU
invoke ShowSpecialFolderPath,CSIDL_STARTUP,addr szCSIDL_STARTUP
invoke ShowSpecialFolderPath,CSIDL_SYSTEM,addr szCSIDL_SYSTEM
invoke ShowSpecialFolderPath,CSIDL_SYSTEMX86 ,addr szCSIDL_SYSTEMX86
invoke ShowSpecialFolderPath,CSIDL_TEMPLATES,addr szCSIDL_TEMPLATES
invoke ShowSpecialFolderPath,CSIDL_WINDOWS,addr szCSIDL_WINDOWS

invoke WriteFile,hstdout,addr notice,sizeof notice-1,addr x,0
invoke ReadFile,hstdin,addr buffer,sizeof buffer,addr x,0

invoke ExitProcess,0
end start
;made at 2011.09.30
*/


EXTERN_C
__declspec(dllexport)
void WINAPI GetSpecialFolderPath()
/*
核心是调用SHGetFolderPathW，再进一步是查询HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions下的对应的GUID的信息。

计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders里是一些Common目录。
计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders里是一些Common目录（路径里带环境变量）。

计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion下有ProgramFilesDir等路径。
类似：计算机\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion。
*/
{
    WCHAR Path[MAX_PATH] = {};
    HWND   hwnd = NULL;
    int    csidl = CSIDL_DESKTOP;
    BOOL   fCreate = FALSE;

    for (; csidl <= CSIDL_COMPUTERSNEARME; csidl++) {
        ZeroMemory(Path, sizeof(Path));
        BOOL ret = SHGetSpecialFolderPathW(hwnd, Path, csidl, fCreate);
        if (ret) {
            printf("%ls\r\n", Path);
        } else {
            printf("csidl:%d, LastError:%d\r\n", csidl, GetLastError());
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
