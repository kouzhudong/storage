#include "Signature.h"


void TestSignature(BCRYPT_RSAKEY_BLOB * PublicKey, 
                   ULONG PublicKeyLen, 
                   BCRYPT_RSAKEY_BLOB * PrivateKey,                   
                   ULONG PrivateKeyLen
)
{
    const char * Data = "test";
    ULONG DataSize = lstrlenA(Data);

    PUCHAR Sign = nullptr;
    ULONG SignSize = 0;

    SignHash((PUCHAR)PrivateKey, PrivateKeyLen, (PUCHAR)Data, DataSize, &Sign, &SignSize);

    VerifySignature((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, Sign, SignSize);
}
