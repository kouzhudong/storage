#include "encrypt.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


int EnumProvidersTest(int argc, _TCHAR * argv[])
/*
²âÊÔÐ§¹û£º
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

    // Enumerate the CryptoAPI and CNG providers.
    hr = EnumProviders();

    CoUninitialize();
    return hr;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
