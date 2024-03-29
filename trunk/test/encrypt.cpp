#include "encrypt.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


int EnumProvidersTest(int argc, _TCHAR* argv[])
/*
测试效果：
 0. CNG: Microsoft Software Key Storage Provider
 1. CNG: Microsoft Passport Key Storage Provider
 2. CNG: Microsoft Smart Card Key Storage Provider
 3. Legacy: Microsoft Base Cryptographic Provider v1.0
 4. Legacy: Microsoft Base DSS and Diffie-Hellman Cryptographic Provider
 5. Legacy: Microsoft Base DSS Cryptographic Provider
 6. Legacy: Microsoft Base Smart Card Crypto Provider
 7. Legacy: Microsoft DH SChannel Cryptographic Provider
 8. Legacy: Microsoft Enhanced Cryptographic Provider v1.0
 9. Legacy: Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider
10. Legacy: Microsoft Enhanced RSA and AES Cryptographic Provider
11. Legacy: Microsoft RSA SChannel Cryptographic Provider
12. Legacy: Microsoft Strong Cryptographic Provider
*/
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    HRESULT hr = S_OK;

    // Initialize COM.
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return hr;
    
    hr = EnumInstalledProviders();// Enumerate the CryptoAPI and CNG providers.

    CoUninitialize();
    return hr;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void MyHandleError(LPCTSTR psz, int nErrorNumber)
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}


int EncryptingFileTest(int argc, _TCHAR * argv[])
/*
Example C Program: Encrypting a File
2018/05/31

The following example encrypts a data file.
The example interactively requests the name of the file that contains plaintext to be encrypted and
the name of a file where the encrypted data is to be written.

The example prompts the user for the names of an input file and an output file.
It also prompts the user for whether a password is to be used to create the encryption session key.
If a password is to be used in the encryption of the data,
the same password must be used in the program that decrypts the file.
For more information, see Example C Program: Decrypting a File.

Due to changing export control restrictions,
the default cryptographic service provider (CSP) and default key length may change between operating system releases.
It is important that both the encryption and decryption use the same CSP and
that the key length be explicitly set to ensure interoperability on different operating system platforms.

This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-encrypting-a-file
*/
{
    if (argc < 3) {
        _tprintf(TEXT("Usage: <example.exe> <source file> ")
                 TEXT("<destination file> | <password>\n"));
        _tprintf(TEXT("<password> is optional.\n"));
        _tprintf(TEXT("Press any key to exit."));
        (void)_gettch();
        return 1;
    }

    LPTSTR pszSource = argv[1];
    LPTSTR pszDestination = argv[2];
    LPTSTR pszPassword = NULL;

    if (argc >= 4) {
        pszPassword = argv[3];
    }

    // Call EncryptFile to do the actual encryption.
    if (MyEncryptFile(pszSource, pszDestination, pszPassword)) {
        _tprintf(TEXT("Encryption of the file %s was successful. \n"), pszSource);
        _tprintf(TEXT("The encrypted data is in file %s.\n"), pszDestination);
    } else {
        MyHandleError(TEXT("Error encrypting file!\n"), GetLastError());
    }

    return 0;
}


int DecryptingFileTest(int argc, _TCHAR * argv[])
/*
Example C Program: Decrypting a File
2018/05/31

The following example shows the decryption of a file.
The example asks the user for the name of an encrypted file and
the name of a file where the decrypted data will be written.
The file with the encrypted data must exist.
The example creates or overwrites the output file.

The example also requests a string that is used as a password.
If a password was used to create the encryption session key,
that same password must be entered to create the decryption session key.
For more information, see Example C Program: Encrypting a File.

Due to changing export control restrictions,
the default cryptographic service provider (CSP) and
default key length may change between operating system releases.
It is important that both the encryption and decryption use the same CSP and
that the key length be explicitly set to ensure interoperability on different operating system platforms.

This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-decrypting-a-file
*/
{
    if (argc < 3) {
        _tprintf(TEXT("Usage: <example.exe> <source file> ")
                 TEXT("<destination file> | <password>\n"));
        _tprintf(TEXT("<password> is optional.\n"));
        _tprintf(TEXT("Press any key to exit."));
        (void)_gettch();
        return 1;
    }

    LPTSTR pszSource = argv[1];
    LPTSTR pszDestination = argv[2];
    LPTSTR pszPassword = NULL;

    if (argc >= 4) {
        pszPassword = argv[3];
    }

    // Call EncryptFile to do the actual encryption.
    if (MyDecryptFile(pszSource, pszDestination, pszPassword)) {
        _tprintf(TEXT("Encryption of the file %s was successful. \n"), pszSource);
        _tprintf(TEXT("The encrypted data is in file %s.\n"), pszDestination);
    } else {
        MyHandleError(TEXT("Error encrypting file!\n"), GetLastError());
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void TestRsa()
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    LPCWSTR AlgId = BCRYPT_RSA_ALGORITHM;// BCRYPT_RSA_SIGN_ALGORITHM
    LPCWSTR Implementation = nullptr;
    ULONG   Flags = 0;
    NTSTATUS NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgId, Implementation, Flags);
    if (STATUS_SUCCESS != NtStatus) {

        return;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG   Length = 3072;//16384
    NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, Length, 0);
    if (STATUS_SUCCESS != NtStatus) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return;
    }    

    //NtStatus = BCryptSetProperty

    NtStatus = BCryptFinalizeKeyPair(hKey, 0);//这个还是很费时的，特别是16384时。
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG KeyPairLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &KeyPairLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * RsaKeyPair = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KeyPairLen);
    _ASSERTE(RsaKeyPair);//前四个字节是：RSA3

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)RsaKeyPair, KeyPairLen, &KeyPairLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Key Pair Len;%d\n", KeyPairLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PrivateKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * PrivateKey = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PrivateKeyLen);
    _ASSERTE(PrivateKey);//前四个字节是：RSA2

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Private Key Len;%d\n", PrivateKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PublicKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * PublicKey = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PublicKeyLen);
    _ASSERTE(PublicKey);//前四个字节是：RSA1

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Public Key Len;%d\n", PublicKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    DWORD BlockLength = 0;
    ULONG Result;
    NtStatus = BCryptGetProperty(
        hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&BlockLength, sizeof(BlockLength), &Result, 0);

    //////////////////////////////////////////////////////////////////////////////////////////////

    const char * Data = "test";
    ULONG DataSize = lstrlenA(Data);
    
    PUCHAR CipherText = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockLength);
    _ASSERTE(CipherText);
    ULONG CipherTextSize = BlockLength;

    PUCHAR PlainText = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockLength);
    _ASSERTE(PlainText);
    ULONG PlainTextSize = BlockLength;

    RsaPublicKeyEncrypt((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, CipherText, CipherTextSize);
    RsaPrivateKeyDecrypt((PUCHAR)PrivateKey, PrivateKeyLen, CipherText, CipherTextSize, PlainText, PlainTextSize);

    //RtlZeroMemory(CipherText, CipherTextSize);
    //RtlZeroMemory(PlainText, PlainTextSize);
    //RsaPrivateKeyEncrypt((PUCHAR)PrivateKey, PrivateKeyLen, (PUCHAR)Data, DataSize, CipherText, CipherTextSize);
    //RsaPublicKeyDecrypt((PUCHAR)PublicKey, PublicKeyLen, CipherText, CipherTextSize, PlainText, PlainTextSize);

    HeapFree(GetProcessHeap(), 0, CipherText);
    HeapFree(GetProcessHeap(), 0, PlainText);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HeapFree(GetProcessHeap(), 0, PublicKey);
    HeapFree(GetProcessHeap(), 0, PrivateKey);
    HeapFree(GetProcessHeap(), 0, RsaKeyPair);

    NtStatus = BCryptDestroyKey(hKey);
    NtStatus = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
