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


bool DelDir(TCHAR * path)
{
    // Check that the input path plus 3 is not longer than MAX_PATH.
    // Three characters are for the "\*" plus NULL appended below.
    size_t length_of_arg;
    StringCchLength(path, MAX_PATH, &length_of_arg);//argv[1]
    if (length_of_arg > (MAX_PATH - 3)) {
        _tprintf(TEXT("\nDirectory path is too long.\n"));
        return false;
    }

    // Prepare string for use with FindFile functions.  
    // First, copy the string to a buffer, then append '\*' to the directory name.
    TCHAR szDir[MAX_PATH];
    StringCchCopy(szDir, MAX_PATH, path);//argv[1]
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
                StringCchCopy(sztemp, MAX_PATH, path);//argv[1]
                PathAppend(sztemp, ffd.cFileName);
                DelDir(sztemp);

                /*_tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName);*/
            }
        } else {
            //LARGE_INTEGER filesize;//这几行显示信息用的，无实际用途。
            //filesize.LowPart = ffd.nFileSizeLow;
            //filesize.HighPart = ffd.nFileSizeHigh;
            //_tprintf(TEXT("  %s   %ld bytes\n"), ffd.cFileName, filesize.QuadPart);

            TCHAR sztemp[MAX_PATH] = {0};
            StringCchCopy(sztemp, MAX_PATH, path);//argv[1]
            PathAppend(sztemp, ffd.cFileName);
            bool b = DeleteFile(sztemp);
            if (b == 0) {
                int x = GetLastError();
                x = x;//查看x的值用的。
            }
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    //dwError = GetLastError();
    //if (dwError != ERROR_NO_MORE_FILES) {
    //    DisplayErrorBox(TEXT("FindFirstFile"));
    //}

    FindClose(hFind);

    return RemoveDirectory(path);//里面有空文件夹依旧任务是空目录。返回0失败。
}


void DelDir2(TCHAR * dir)
{
    if (!PathFileExists(dir)) {
        return;
    }

    TCHAR DelDir[MAX_PATH] = {0};
    lstrcpy(DelDir, dir);
    int len = lstrlen(dir);
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


int DelDirTest(int argc, TCHAR * argv[])
/*
删除文件夹有两种办法：
1.递归遍历加RemoveDirectory（移除空目录）。只读属性需要去掉。
2.SHFileOperation函数的FO_DELETE。
修改自：http://msdn.microsoft.com/en-us/library/windows/desktop/aa365200(v=vs.85).aspx等。

If you are writing a 32-bit application to list all the files in a directory and the application may be run on a 64-bit computer,
you should call the Wow64DisableWow64FsRedirectionfunction before calling FindFirstFile and call Wow64RevertWow64FsRedirection after the last call to FindNextFile.
*/
{
    setlocale(LC_CTYPE, ".936");

    TCHAR path[MAX_PATH] = L"e:\\test";

    bool b = DelDir(path);

    DelDir2((TCHAR *)L"e:\\test2");

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
