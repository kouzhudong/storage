#include "Hash.h"


void HashTest()
{
    const char * test = "test";
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL ret = CngHashData(BCRYPT_SHA256_ALGORITHM, (PUCHAR)test, lstrlenA(test), &Hash, &HashSize);
    if (ret && Hash) {
        PrintBytes(Hash, HashSize);
    }

    if (Hash) {
        HeapFree(GetProcessHeap(), 0, Hash);
    }
}
