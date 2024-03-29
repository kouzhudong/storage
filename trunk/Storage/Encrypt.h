/*
此加密非操作系统自带的驱动级别的磁盘和文件的那个透明加解密。

而是正常的加解密。
*/

#pragma once

class Encrypt
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


//SDK中没有Sslprovider.h。
typedef SECURITY_STATUS (WINAPI * SslEnumProtocolProviders_fn)(
    _Out_ DWORD * pdwProviderCount,
    _Out_ NCryptProviderName ** ppProviderList,
    _In_  DWORD              dwFlags
);

typedef SECURITY_STATUS (WINAPI * SslFreeBuffer_fn)(
    _In_ PVOID pvInput
);

typedef SECURITY_STATUS (WINAPI * SslOpenProvider_Fn)(
  _Out_ NCRYPT_PROV_HANDLE *phSslProvider,
  _In_  LPCWSTR            pszProviderName,
  _In_  DWORD              dwFlags
);

//SECURITY_STATUS WINAPI SslEnumCipherSuites(
//  _In_     NCRYPT_PROV_HANDLE      hSslProvider,
//  _In_opt_ NCRYPT_KEY_HANDLE       hPrivateKey,
//  _Out_    NCRYPT_SSL_CIPHER_SUITE **ppCipherSuite,
//  _Inout_  PVOID                   *ppEnumState,
//  _In_     DWORD                   dwFlags
//);


//////////////////////////////////////////////////////////////////////////////////////////////////


#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 


//////////////////////////////////////////////////////////////////////////////////////////////////
