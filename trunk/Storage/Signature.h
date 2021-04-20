/*
����ǩ����˵�ļ��仰��
1.���ܼ��PE�ṹ�����жϣ��мٵ�α���ǩ����
2.�кܶ��ǩ����ǩ����Ϣ����������CAT��
3.һ���ļ������ж��CAT��
4.һ���ļ�����CAT�ж��ǩ����
5.ǩ����Ȼ�벻��֤�飬����Ҳ��֤��Ĵ������ӡ�
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
