#include "pch.h"
#include "Zip.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void zip(BSTR source, BSTR dest)
/*
source�������ļ�Ҳ�������ļ���.
dest�ĺ�׺��������ZIP.

ȱ�㣺��֪��ʱ������
*/
{
    //ȷ��sourceĿ¼����.
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
��һ��ZIPѹ���ļ���ѹ��ָ�����ļ���.

ȱ�㣺��֪��ʱ������
*/
{
    //ȷ��destĿ¼����.
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
ѹ����һ��������㷨,�������Ǽ������ѧ.
���ҵ���ä����ֹ��.

�ɱ���ҿɲ�֪ѹ��,������˶����õĿ�Դ���㷨(��).

���򲻵��Ѷ���֮,��ʵ��Ҳ������.

֪��WIN 8��ѹ���ĺ���.

ǰЩʱ�Ϸ���XPҲ��,ֻ��һCOM����ʽ�ṩ.

����,���ǲ�֪��ɶʱ��ѻ����,
���ǸĽ�֮��.

�������д��Ľ�,�緵�ص�����,������ж�,����ʵ������ȷ�Ŀ��õ�.

made by correy
made at 2013.12.23
*/
{
    zip((BSTR)L"d:\\test1", (BSTR)L"d:\\test.zip");//\0\0 \\\0\0
    unzip((BSTR)L"d:\\test.zip", (BSTR)L"d:\\test2");//\\\0\0  \\\0\0
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
