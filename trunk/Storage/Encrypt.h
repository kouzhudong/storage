/*
�˼��ܷǲ���ϵͳ�Դ�����������Ĵ��̺��ļ����Ǹ�͸���ӽ��ܡ�

���������ļӽ��ܡ�
*/

#pragma once

class Encrypt
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


//SDK��û��Sslprovider.h��
typedef SECURITY_STATUS (WINAPI * SslEnumProtocolProviders_fn)(
    _Out_ DWORD * pdwProviderCount,
    _Out_ NCryptProviderName ** ppProviderList,
    _In_  DWORD              dwFlags
);

typedef SECURITY_STATUS (WINAPI * SslFreeBuffer_fn)(
    _In_ PVOID pvInput
);


//////////////////////////////////////////////////////////////////////////////////////////////////


#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


//////////////////////////////////////////////////////////////////////////////////////////////////
