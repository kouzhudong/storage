#include "Signature.h"


void TestSignature()
/*
功能：签名和验签的测试。

心得：
1.签名的哈希不能是BCRYPT_SHA256_ALGORITHM，只能是BCRYPT_SHA1_ALGORITHM。
2.签名的算法不能是BCRYPT_RSA_ALGORITHM和BCRYPT_RSA_SIGN_ALGORITHM。
3.签名算法测试成功的有BCRYPT_DSA_ALGORITHM（3072和2048失败）和BCRYPT_ECDSA_P256_ALGORITHM。

参考：
1.https://docs.microsoft.com/zh-cn/windows/win32/seccng/signing-data-with-cng
2.Windows-classic-samples\Samples\Security\SignHashAndVerifySignature
3.ProcessHacker
*/
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
    ULONG   Length = 1024;
    NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, Length, 0);
    if (STATUS_SUCCESS != NtStatus) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return;
    }

    //NtStatus = BCryptSetProperty

    NtStatus = BCryptFinalizeKeyPair(hKey, 0);//这个还是很费时的。
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PrivateKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PRIVATE_BLOB, NULL, 0, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    PBCRYPT_DSA_KEY_BLOB PrivateKey = (PBCRYPT_DSA_KEY_BLOB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PrivateKeyLen);
    _ASSERTE(PrivateKey);

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Private Key Len;%d\n", PrivateKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PublicKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, NULL, 0, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    PBCRYPT_DSA_KEY_BLOB PublicKey = (PBCRYPT_DSA_KEY_BLOB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PublicKeyLen);
    _ASSERTE(PublicKey);

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
    _ASSERTE(STATUS_SUCCESS == NtStatus);

    printf("Public Key Len;%d\n", PublicKeyLen);

    //////////////////////////////////////////////////////////////////////////////////////////////

    const char * Data = "test";
    ULONG DataSize = lstrlenA(Data);

    PUCHAR Sign = nullptr;
    ULONG SignSize = 0;

    SignHash((PUCHAR)PrivateKey, PrivateKeyLen, (PUCHAR)Data, DataSize, &Sign, &SignSize);

    VerifySignature((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, Sign, SignSize);

    HeapFree(GetProcessHeap(), 0, Sign);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HeapFree(GetProcessHeap(), 0, PublicKey);
    HeapFree(GetProcessHeap(), 0, PrivateKey);

    NtStatus = BCryptDestroyKey(hKey);
    NtStatus = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}
