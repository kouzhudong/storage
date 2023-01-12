#include "pch.h"
#include "Zip.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void zip(BSTR source, BSTR dest)
/*
source可以是文件也可以是文件夹.
dest的后缀名必须是ZIP.

缺点：不知何时结束。
*/
{
    //确保source目录存在.
    if (!PathFileExists(source)) {
        return;
    }

    // Create Zip file
    BYTE startBuffer[] = {80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    HANDLE hFile = CreateFile(dest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open file (error %d)\n", GetLastError());
        return;
    }
    DWORD dwResult;
    if (!WriteFile(hFile, startBuffer, sizeof(startBuffer), &dwResult, NULL)) {
        printf("Could not write to file (error %d)\n", GetLastError());
        return;
    }
    if (!CloseHandle(hFile)) {
        printf("Could not close to file (error %d)\n", GetLastError());
        return;
    }

    (void)CoInitialize(NULL);

    IShellDispatch * pISD;
    HRESULT hResult = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void **)&pISD);
    if (SUCCEEDED(hResult)) {
        VARIANT          vDir;
        VariantInit(&vDir);
        vDir.vt = VT_BSTR;
        vDir.bstrVal = dest;//L"C:\\test.zip\\\0\0";

        Folder * pToFolder = NULL;
        hResult = pISD->NameSpace(vDir, &pToFolder);
        if (SUCCEEDED(hResult)) {
            VARIANT vFile, vOpt;

            VariantInit(&vFile);
            vFile.vt = VT_BSTR;
            vFile.bstrVal = source;//L"C:\\test.txt";			

            VariantInit(&vOpt);
            vOpt.vt = VT_I4;
            vOpt.lVal = 4;//FOF_NO_UI;          // Do not display a progress dialog box, not useful in our example

            // Now copy source file(s) to the zip
            // ******NOTE**** To copy multiple files into the zip, need to create a FolderItems object (see unzip implementation below for more details)
            hResult = pToFolder->CopyHere(vFile, vOpt);// Copying and compressing the source files to our zip

            /* CopyHere() creates a separate thread to copy files and it may happen that the main thread exits before the copy thread is initialized.
            So we put the main thread to sleep for a second to give time for the copy thread to start.*/
            Sleep(1000);
            pToFolder->Release();
        }

        pISD->Release();
    }

    CoUninitialize();
}


void unzip(BSTR source, BSTR dest)
/*
把一个ZIP压缩文件解压到指定的文件夹.

缺点：不知何时结束。
*/
{
    //确保dest目录存在.
    if (!PathFileExists(dest)) {
        return;
    }

    (void)CoInitialize(NULL);

    IShellDispatch * pISD;
    HRESULT hResult = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void **)&pISD);
    if (SUCCEEDED(hResult)) {
        VARIANT vDir;
        VariantInit(&vDir);
        vDir.vt = VT_BSTR;
        vDir.bstrVal = dest;//L"C:\\test.zip\\\0\0";

        Folder * pToFolder = NULL;
        hResult = pISD->NameSpace(vDir, &pToFolder);
        if (SUCCEEDED(hResult)) {
            VARIANT vFile;
            VariantInit(&vFile);
            vFile.vt = VT_BSTR;
            vFile.bstrVal = source;//L"C:\\test.txt";

            Folder * pFromFolder = NULL;
            pISD->NameSpace(vFile, &pFromFolder);

            FolderItems * fi = NULL;
            pFromFolder->Items(&fi);

            VARIANT vOpt;
            VariantInit(&vOpt);
            vOpt.vt = VT_I4;
            vOpt.lVal = 4;//FOF_NO_UI; // Do not display a progress dialog box

            // Creating a new Variant with pointer to FolderItems to be copied
            VARIANT newV;
            VariantInit(&newV);
            newV.vt = VT_DISPATCH;
            newV.pdispVal = fi;

            hResult = pToFolder->CopyHere(newV, vOpt);

            Sleep(1000);
            pFromFolder->Release();
            pToFolder->Release();
        }

        pISD->Release();
    }

    CoUninitialize();
}


int TestZip()
/*
压缩是一个高深的算法,可以是是计算机科学.
令我等文盲望而止步.

干编程且可不知压缩,大多数人都是用的开源的算法(库).

这万不得已而用之,其实我也不想用.

知道WIN 8有压缩的函数.

前些时断发现XP也有,只是一COM的形式提供.

不错,就是不知它啥时候把活干完,
这是改进之处.

函数还有待改进,如返回的类型,错误的判断,但是实验是正确的可用的.

made by correy
made at 2013.12.23
*/
{
    zip((BSTR)L"d:\\test1", (BSTR)L"d:\\test.zip");//\0\0 \\\0\0
    unzip((BSTR)L"d:\\test.zip", (BSTR)L"d:\\test2");//\\\0\0  \\\0\0
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
