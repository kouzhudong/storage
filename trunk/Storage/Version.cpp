#include "pch.h"
#include "Version.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI GetFileVersion(PWCHAR FileName, VS_FIXEDFILEINFO * FileInfo)
/*
���ܣ���ȡ�ļ��İ汾��Ϣ��

�ο���\Windows-classic-samples\Samples\Win7Samples\sysmgmt\msi\setup.exe\utils.cpp��GetFileVersionNumber������
*/
{
    DWORD lpdwHandle = 0;
    DWORD D = GetFileVersionInfoSize(FileName, &lpdwHandle);
    if (!D) {
        //LOGW(ERROR_LEVEL, "FileName:%ls, GetLastError:%#x", FileName, GetLastError());
        return;
    }

    LPVOID lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, D);
    if (NULL == lpData) {
        //LOGA(ERROR_LEVEL, "�����ڴ�ʧ��");
        return;
    }

    BOOL B = GetFileVersionInfo(FileName, 0, D, lpData);
    if (!B) {
        //LOGW(ERROR_LEVEL, "FileName:%ls, GetLastError:%#x", FileName, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    VS_FIXEDFILEINFO * lpVSFixedFileInfo = NULL;
    unsigned          uiSize;
    B = VerQueryValue(lpData, L"\\", (LPVOID *)&lpVSFixedFileInfo, &uiSize) && (uiSize != 0);
    if (!B) {
        //LOGW(ERROR_LEVEL, "FileName:%ls, GetLastError:%#x", FileName, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    *FileInfo = *lpVSFixedFileInfo;

    HeapFree(GetProcessHeap(), 0, lpData);
}


EXTERN_C
__declspec(dllexport)
void WINAPI GetFileResourcesW(IN LPCWSTR FileName, IN LPCWSTR ResourceName)
/*
���ܣ���ȡ�ļ���Դ��һЩ��Ϣ��

������
FileName �ļ�����ע�⣺��ʱ�ᴫ�ݹ�����\SystemRoot\System32\smss.exe��
ResourceName ��Դ�����������д��֧�ֵ�ѡ���У�
    Comments
    InternalName
    ProductName
    CompanyName
    LegalCopyright
    ProductVersion
    FileDescription
    LegalTrademarks
    PrivateBuild
    FileVersion
    OriginalFilename
    SpecialBuild��
result ��Ҫ�Ľ����ע���ַ��ı��룬�е��Ǻ��֣��е��������ַ���

�ο���
1.\Windows-classic-samples\Samples\Win7Samples\sysmgmt\msi\setup.exe\utils.cpp��GetFileVersionNumber������
2.https://docs.microsoft.com/en-us/windows/win32/api/winver/nf-winver-verqueryvaluea
3.https://blog.csdn.net/Simon798/article/details/102836496

��Ϊ���������ַ�����ansi���ܱ�ʾ�����ַ������Բ�����A��ģ�ֻ��W�汾�ġ�
*/
{
    DWORD lpdwHandle = 0;
    DWORD D = GetFileVersionInfoSize(FileName, &lpdwHandle);
    if (!D) {//0x715 == �Ҳ���ӳ���ļ���ָ������Դ���͡�
        DWORD LastError = GetLastError();
        if (ERROR_RESOURCE_TYPE_NOT_FOUND != LastError && ERROR_FILE_NOT_FOUND != LastError) {
            //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, LastError);
        }
        return;
    }

    LPVOID lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, D);
    if (NULL == lpData) {
        //LOGA(ERROR_LEVEL, "�����ڴ�ʧ��");
        return;
    }

    BOOL B = GetFileVersionInfo(FileName, 0, D, lpData);
    if (!B) {
        //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, GetLastError());
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    // Read the list of languages and code pages.
    unsigned cbTranslate;
    B = VerQueryValue(lpData, L"\\VarFileInfo\\Translation", (LPVOID *)&lpTranslate, &cbTranslate);
    if (!B) {
        DWORD LastError = GetLastError();
        if (ERROR_RESOURCE_TYPE_NOT_FOUND == LastError || ERROR_FILE_NOT_FOUND == LastError) {
            //DbgPrintA("���棺FileName:%ls, LastError:%#x", FileName, LastError);
        } else {
            //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, LastError);
        }
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    // Read the file description for each language and code page.
    int count = (cbTranslate / sizeof(struct LANGANDCODEPAGE));

    if (0 == count) {
        HeapFree(GetProcessHeap(), 0, lpData);
        return;
    }

    if (count > 1) {
        //DbgPrintA("��Ҫ��Ϣ��FileName:%ls, �ļ�������Ĵ���ҳ/���Ե�����֧�ֶ��, count:%#x", FileName, count);
    }

    for (int i = 0; i < count; i++) {
        WCHAR SubBlock[MAX_PATH] = {0};
        HRESULT hr = StringCchPrintf(SubBlock,
                                     MAX_PATH,
                                     L"\\StringFileInfo\\%04x%04x\\%s",
                                     lpTranslate[i].wLanguage,
                                     lpTranslate[i].wCodePage,
                                     ResourceName);
        if (FAILED(hr)) {
            //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, GetLastError());
            break;
        }

        // Retrieve file description for language and code page "i". 
        VS_FIXEDFILEINFO * lpBuffer = NULL;
        unsigned          dwBytes;
        B = VerQueryValue(lpData, SubBlock, (LPVOID *)&lpBuffer, &dwBytes);
        if (!B) {//YourPhoneServer.exe �� YourPhone.exe��������Դȴ����0x715��
            DWORD LastError = GetLastError();
            if (ERROR_RESOURCE_TYPE_NOT_FOUND != LastError) {
                //LOGA(ERROR_LEVEL, "FileName:%ls, LastError:%#x", FileName, LastError);
            }
            break;
        }

        printf("%ls", (PWCHAR)lpBuffer);
    }

    HeapFree(GetProcessHeap(), 0, lpData);
}
