#include "pch.h"


void PrintBytes(IN BYTE * pbPrintData, IN DWORD cbDataLen)
/*

https://docs.microsoft.com/zh-cn/windows/win32/seccng/encrypting-data-with-cng
*/
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen; dwCount++) {
        printf("0x%02x, ", pbPrintData[dwCount]);

        if (0 == (dwCount + 1) % 16)
            putchar('\n');
    }
}
