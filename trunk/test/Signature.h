#pragma once

#include "..\inc\Storage.h"
#include "pch.h"

class Signature
{

};

void TestSignature(BCRYPT_RSAKEY_BLOB * PublicKey, 
                   ULONG PublicKeyLen, 
                   BCRYPT_RSAKEY_BLOB * PrivateKey,                   
                   ULONG PrivateKeyLen
);
