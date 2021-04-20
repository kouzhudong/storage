/*
关于签名想说的几句话：
1.不能检测PE结构进行判断，有假的伪造的签名。
2.有很多的签名的签名信息不在自身，如CAT。
3.一个文件可以有多个CAT。
4.一个文件或者CAT有多个签名。
5.签名自然离不开证书，这里也有证书的代码例子。
*/


#pragma once


class __declspec(dllexport) Signature
{
public:

};


//////////////////////////////////////////////////////////////////////////////////////////////////


#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)


typedef struct {
    LPWSTR lpszProgramName;
    LPWSTR lpszPublisherLink;
    LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, * PSPROG_PUBLISHERINFO;


typedef struct _ENUM_ARG {
    BOOL        fAll;
    BOOL        fVerbose;
    DWORD       dwFlags;
    const void * pvStoreLocationPara;
    HKEY        hKeyBase;
} ENUM_ARG, * PENUM_ARG;


// Copyright (C) Microsoft.  All rights reserved.
// This example demonstrates how to create and encode a certificate request. 
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


//   This program use this additional #define statement. 
#define CERT_SUBJECT_NAME "This certificate user"


#define MY_TYPE   X509_ASN_ENCODING


#define MY_STRING_TYPE (CERT_OID_NAME_STR)


#define MY_CONTAINER_NAME TEXT("testcapiservicemachinecontainer")


//////////////////////////////////////////////////////////////////////////////////////////////////
