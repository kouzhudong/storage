#pragma once

class Certificate
{

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


//   This program use this additional #define statement. 
#define CERT_SUBJECT_NAME "This certificate user"


#define MY_TYPE   X509_ASN_ENCODING


#define MY_STRING_TYPE (CERT_OID_NAME_STR)


#define MY_CONTAINER_NAME TEXT("testcapiservicemachinecontainer")


//////////////////////////////////////////////////////////////////////////////////////////////////
