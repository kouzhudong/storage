#include "Signature.h"


void TestSignature()
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    LPCWSTR AlgId = BCRYPT_DSA_ALGORITHM;//BCRYPT_ECDSA_P521_ALGORITHM BCRYPT_RSA_SIGN_ALGORITHM
    LPCWSTR Implementation = nullptr;
    ULONG   Flags = 0;
    NTSTATUS NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgId, Implementation, Flags);
    if (STATUS_SUCCESS != NtStatus) {

        return;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG   Length = 1024;//16384
    NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, Length, 0);
    if (STATUS_SUCCESS != NtStatus) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return;
    }

    //NtStatus = BCryptSetProperty

    NtStatus = BCryptFinalizeKeyPair(hKey, 0);//这个还是很费时的，特别是16384时。
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    //ULONG KeyPairLen = 0;
    //NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &KeyPairLen, 0);
    //_ASSERTE(STATUS_SUCCESS == NtStatus);

    //BCRYPT_RSAKEY_BLOB * RsaKeyPair = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KeyPairLen);
    //_ASSERTE(RsaKeyPair);//前四个字节是：RSA3

    //NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)RsaKeyPair, KeyPairLen, &KeyPairLen, 0);
    //_ASSERTE(STATUS_SUCCESS == NtStatus);

    //printf("Key Pair Len;%d\n", KeyPairLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PrivateKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PRIVATE_BLOB, NULL, 0, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * PrivateKey = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PrivateKeyLen);
    _ASSERTE(PrivateKey);//前四个字节是：RSA2

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Private Key Len;%d\n", PrivateKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PublicKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, NULL, 0, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * PublicKey = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PublicKeyLen);
    _ASSERTE(PublicKey);//前四个字节是：RSA1

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Public Key Len;%d\n", PublicKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    //DWORD BlockLength = 0;
    //ULONG Result;
    //NtStatus = BCryptGetProperty(
    //    hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&BlockLength, sizeof(BlockLength), &Result, 0);
    //_ASSERTE(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    const char * Data = "test";
    ULONG DataSize = lstrlenA(Data);

    PUCHAR Sign = nullptr;
    ULONG SignSize = 0;

    SignHash((PUCHAR)PrivateKey, PrivateKeyLen, (PUCHAR)Data, DataSize, &Sign, &SignSize);

    VerifySignature((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, Sign, SignSize);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HeapFree(GetProcessHeap(), 0, PublicKey);
    HeapFree(GetProcessHeap(), 0, PrivateKey);
    //HeapFree(GetProcessHeap(), 0, RsaKeyPair);

    NtStatus = BCryptDestroyKey(hKey);
    NtStatus = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}
