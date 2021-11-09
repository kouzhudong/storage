#include "pch.h"
#include "Signature.h"


#pragma warning(disable:28182)
#pragma warning(disable:28183)
#pragma warning(disable:6387)
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#pragma warning(disable:6054)
#pragma warning(disable:6386)


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
PCCERT_CONTEXT WINAPI GetSignerCert(HCERTSTORE hCertStore)
/*
GetSignerCert
2018/05/31

//   Parameter passed in:
//      hCertStore, the handle of the store to be searched.

The GetSignerCert function goes through (enumerates) the certificates in a certificate store until a certificate with a signature key is found.
If a certificate is found, a pointer to the certificate is returned. This code demonstrates:

Finding a certificate with a certificate property.
Checking that property.
Returning a pointer to the CERT_CONTEXT where the attribute was found.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/getsignercert?redirectedfrom=MSDN
*/
{
    //   Declare and initialize local variables.
    PCCERT_CONTEXT       pCertContext = NULL;
    BOOL                 fMore = TRUE;
    DWORD                dwSize = NULL;
    CRYPT_KEY_PROV_INFO * pKeyInfo = NULL;
    DWORD                PropId = CERT_KEY_PROV_INFO_PROP_ID;

    //  Find certificates in the store until the end of the store
    //  is reached or a certificate with an AT_SIGNATURE key is found.
    while (fMore && (pCertContext = CertFindCertificateInStore(
        hCertStore,           // Handle of the store to be searched.
        0,                    // Encoding type. Not used for this search.
        0,                    // dwFindFlags. Special find criteria.
                              // Not used in this search.
        CERT_FIND_PROPERTY,   // Find type that determines the kind of search to do. 
                              // In this case, search for certificates that have a specific 
                              // extended property.
        &PropId,              // pvFindPara. Gives the specific 
                              // value searched for, here the identifier of an extended property.
        pCertContext)))       // pCertContext is NULL for the first call to the function. 
                              // If the function is called in a loop, after the first call
                              // pCertContext is the certificate returned by the previous call.
    {
        // For simplicity, this code only searches 
        // for the first occurrence of an AT_SIGNATURE key. 
        // In many situations, a search would also look for a 
        // specific subject name as well as the key type.

        // Call CertGetCertificateContextProperty once to get the returned structure size.
        if (!(CertGetCertificateContextProperty(
            pCertContext,
            CERT_KEY_PROV_INFO_PROP_ID,
            NULL,
            &dwSize))) {
            MyHandleError("Error Getting Key Property");
        }

        // Allocate memory for the returned structure.
        if (pKeyInfo)
            free(pKeyInfo);
        if (!(pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize))) {
            MyHandleError("Error Allocating Memory for pKeyInfo");
        }

        // Get the key information structure.
        if (!(CertGetCertificateContextProperty(pCertContext,
                                                CERT_KEY_PROV_INFO_PROP_ID,
                                                pKeyInfo,
                                                &dwSize))) {
            MyHandleError("The second call to the function failed.");
        }

        // Check the dwKeySpec member for a signature key.
        if (pKeyInfo->dwKeySpec == AT_SIGNATURE) {
            fMore = FALSE;
        }
    }  // End of while loop

    if (pKeyInfo)
        free(pKeyInfo);

    return (pCertContext);
}  // End of GetSignerCert


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Other Extended C Code Examples
2018 / 05 / 31

The following topics present other procedures and 
extended C code examples that use the CryptoAPI functions :

Verifying a CTL
Verifying Signed Messages by Using CTLs
Example C Program : Certificate Verification Operations
Example C Program : Working with Key Identifiers
Example C Program : Creating a Certificate Chain
Example C Program : Making a Certificate Request
Example C Program : ASN.1 Encoding and Decoding
Example C Program : Using CertOIDToAlgId and CertCompareIntegerBlob
Example C Program : Verifying the Signature of a PE File
Modifying Key Container Access
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


void CertificateVerificationOperations(void)
/*
Example C Program: Certificate Verification Operations
05/31/2018

//  Copyright (C) Microsoft.  All rights reserved.
//  This example demonstrates:
//      1. Opening and closing a system store.
//      2. Finding a certificate by subject name.
//      3. Using the CertVerifyTimeValidity function to check the certificate's time validity.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-certificate-verification-operations
*/
{
    // Declare and initialize variables.
    HCERTSTORE      hSystemStore;
    PCCERT_CONTEXT  pTargetCert = NULL;
    PCERT_INFO      pTargetCertInfo;
    char            szSubjectName[] = "Insert_cert_subject_name1";
    // String to be found in a certificate subject

    // Call CertOpenStore to open the CA store.
    if (hSystemStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"CA")) {
        printf("CertOpenStore succeeded. The CA store is open. \n");
    } else {
        MyHandleError("Error opening the Root store.");
    }

    // Get a particular certificate using CertFindCertificateInStore.
    if (pTargetCert = CertFindCertificateInStore(
        hSystemStore,           // Store handle.
        MY_ENCODING_TYPE,       // Encoding type.
        0,                      // Not used.
        CERT_FIND_SUBJECT_STR_A,// Find type. Find a string in the certificate's subject.
        szSubjectName,          // The string to be searched for.
        pTargetCert))           // Previous context.
    {
        printf("Found the certificate. \n");
    } else {
        MyHandleError("Could not find the required certificate");
    }

    // pTargetCert is a pointer to the desired certificate.
    // Check the certificate's time validity.
    pTargetCertInfo = pTargetCert->pCertInfo;
    switch (CertVerifyTimeValidity(NULL,               // Use current time.
                                   pTargetCertInfo))   // Pointer to CERT_INFO.
    {
    case -1:
    {
        printf("Certificate is not valid yet. \n");
        break;
    }
    case 1:
    {
        printf("Certificate is expired. \n");
        break;
    }
    case 0:
    {
        printf("Certificate's time is valid. \n");
        break;
    }
    };

    // Clean up memory and quit.
    if (pTargetCert)
        CertFreeCertificateContext(pTargetCert);
    if (hSystemStore) {
        if (!CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG))
            MyHandleError("Could not close the certificate store");
    }
    printf("The certificate has been freed and the store closed. \n");
    printf("The certificate verification program ran to completion without error. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// This program demonstrates the following Key Identifier functions:
//         CryptCreateKeyIdentifierFromCSP
//         CryptSetKeyIdentifierProperty
//         CryptGetKeyIdentifierProperty
//         CryptEnumKeyIdentifierProperties
// The callback function pfnEnum is also demonstrated.


// Declare the Callback function
static BOOL WINAPI pfnEnum(
    const CRYPT_HASH_BLOB * pKeyIdentifier, // in- pKeyIdentifier
    DWORD dwFlags,                         // in- Flag values
    void * pvReserved,                      // Reserved
    void * pvArg,                           // in- Pass-through argument
    DWORD cProp,                           // in- cProp
    DWORD * rgdwPropId,                     // in- array of PropIds
    void ** rgpvData,                       // in- array of CRYPT_KEY_PROV_INFO structures
    DWORD * rgcbData                        // in- rgcbData
);


void WorkingKeyIdentifiers(void)
/*
Example C Program: Working with Key Identifiers
05/31/2018

The following example demonstrates ways of working with key identifiers.
This example illustrates the following tasks and CryptoAPI functions:

Creating a key identifier using CryptCreateKeyIdentifierFromCSP.
Setting a property on a key identifier using CryptSetKeyIdentifierProperty.
Retrieving the contents of a key identifier property using CryptGetKeyIdentifierProperty.
Listing the properties of a key identifier using CryptEnumKeyIdentifierProperties.
Declaring, defining, and using a callback function.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-working-with-key-identifiers
*/
{
    // Declare and initialize variables.
    PUBLICKEYSTRUC * pPubKeyStruc;
    DWORD cbPubKeyStruc = sizeof(PUBLICKEYSTRUC);
    if (!(pPubKeyStruc = (PUBLICKEYSTRUC *)malloc(cbPubKeyStruc)))
        MyHandleError("Memory allocation failed.");

    pPubKeyStruc->bType = PUBLICKEYBLOB;
    pPubKeyStruc->bVersion = CUR_BLOB_VERSION;
    pPubKeyStruc->reserved = 0;
    pPubKeyStruc->aiKeyAlg = CALG_RSA_KEYX;

    BYTE * pbHash;
    DWORD cbHash;
    PCRYPT_KEY_PROV_INFO pData;

    CRYPT_HASH_BLOB KeyIdentifier;

    DWORD cbData;
    void * pvArg;         // Pass through argument.
    cbHash = 20;          // define cbHash to the size of a SHA1
                         // string- there is no need for a 2 pass　call to determine size of cbHash.

    // Allocate memory for the pbHash buffer
    if (!(pbHash = (BYTE *)malloc(cbHash)))
        MyHandleError("Memory allocation failed.");

    // Create a Key Identifier
    if (CryptCreateKeyIdentifierFromCSP(
        X509_ASN_ENCODING, // dwCertEncodingType
        NULL,              // pszPubKeyOID- NULL to use default OID.
        pPubKeyStruc,      // pPubKeyStruc- defined above
        cbPubKeyStruc,     // cbPubKeyStruc
        0,                 // dwFlags
        NULL,              // pvReserved
        pbHash,            // pbHash
        &cbHash            // pcbHash
    )) {
        printf("Call to CryptCreateKeyIdentifierFromCSP succeeded.\n");
    } else {
        MyHandleError("A key identifier was not created");
    }

    // Set the members of the key identifier.
    KeyIdentifier.cbData = cbHash;
    KeyIdentifier.pbData = (BYTE *)pbHash;

    // Initialize the pdata structure.
    if (!(pData = (CRYPT_KEY_PROV_INFO *)malloc(sizeof(CRYPT_KEY_PROV_INFO))))
        MyHandleError("Memory allocation failed.");
    pData->pwszContainerName = (LPWSTR)L"New Key container name";
    pData->pwszProvName = (LPWSTR)MS_ENHANCED_PROV_W;
    pData->dwProvType = PROV_RSA_FULL;
    pData->dwFlags = 0;
    pData->cProvParam = 0;
    pData->rgProvParam = NULL;
    pData->dwKeySpec = AT_SIGNATURE;

    // Set a property on the created key identifier.
    if (CryptSetKeyIdentifierProperty(
        &KeyIdentifier,             // in- defined above
        CERT_KEY_PROV_INFO_PROP_ID, // in- dwPropId
        CRYPT_KEYID_MACHINE_FLAG,   // in- dwFlags- use local computer
        NULL,                       // in- pwszComputerName
        NULL,                       // Reserved
        pData                       // in- pointer to a CRYPT_KEY_PROV_INFO.
    )) {
        printf("A property is set on the key identifier.\n");
    } else {
        MyHandleError("Setting the property failed.");
    }

    // Call CryptGetKeyIdentifierProperty to set the size of the property to be retrieved.
    if (CryptGetKeyIdentifierProperty(
        &KeyIdentifier,             // in- defined above
        CERT_KEY_PROV_INFO_PROP_ID, // in- dwPropId
        CRYPT_KEYID_MACHINE_FLAG,   // in- dwFlags
        NULL,                       // in, optional- pwszComputerName
        NULL,                       // in, optional- pvReserved
        NULL,                       // out- pvData
        &cbData                     // in, out- pcbData
    )) {
        printf("First call to get property succeeded.\n");
    } else {
        MyHandleError("Call 1 to CryptGetKeyIdentifierProperty failed.");
    }

    free(pData);// Free the memory allocated for pData,

    // Allocate memory for the buffer to receive the property.
    if (!(pData = (CRYPT_KEY_PROV_INFO *)malloc(cbData)))
        MyHandleError("Memory allocation failed.");

    // Call CryptGetKeyIdentifierProperty a second time
    // To retrieve the property into the allocated buffer.
    if (CryptGetKeyIdentifierProperty(
        &KeyIdentifier,             // pKeyIdentifier
        CERT_KEY_PROV_INFO_PROP_ID, // dwPropId
        CRYPT_KEYID_MACHINE_FLAG,   // dwFlags
        NULL,                       // pwszComputerName
        NULL,                       // Reserved
        pData,                      // pData
        &cbData                     // pcbData
    )) {
        printf("The property has been retrieved.\n");
    } else {
        MyHandleError("Second call failed.");
    }

    // Print part of the retrieved property.
    printf("Some of the properties obtained are;\n");
    printf("container name= %S\n", pData->pwszContainerName);
    printf("Provider name= %S\n", pData->pwszProvName);
    printf("Provider type= %i\n", pData->dwProvType);
    printf("length= %i\n\n", cbData);

    // Set the pass through argument for the callback function.
    pvArg = pPubKeyStruc;

    // Call CryptEnumKeyIdentifierProperties.
    printf("\nCalling CryptEnumKeyIdentifierProperties.\n");
    if (CryptEnumKeyIdentifierProperties(
        &KeyIdentifier,           // in- pKeyIdentifier-
        0,                        // in- dwPropId
        CRYPT_KEYID_MACHINE_FLAG, // in- dwFlags, use LocalMachine.
        NULL,                     // in, optional- pwszComputerName set to NULL to use LocalMachine.
        NULL,                     // Reserved
        pvArg,                    // in, optional- Pointer to the pass-through argument
        (PFN_CRYPT_ENUM_KEYID_PROP)pfnEnum// in- Callback function.
    )) {
        printf("The function call succeeded.\n");
    } else {
        MyHandleError("Call to CryptEnumKeyIdentifierProperties failed.");
    }

    // Free all allocated memory
    free(pData);
    free(pPubKeyStruc);
    printf("all memory free\n");
    printf("The program ran to completion without error.\n");
}


static BOOL WINAPI pfnEnum(
    const CRYPT_HASH_BLOB * pKeyIdentifier, // in- pKeyIdentifier
    DWORD dwFlags,                         // in- Flag values
    void * pvReserved,                      // Reserved
    void * pvArg,                           // in- Pass-through argument
    DWORD cProp,                           // in- cProp
    DWORD * rgdwPropId,                     // in- rgdwPropId
    void ** rgpvData,                       // in- rgpvData- points to an array of CRYPT_KEY_PROV_INFO  structures
    DWORD * rgcbData                        // in- rgcbData
)
// Define the Callback function
{
    //  Declare and initialize local variables.
    PUBLICKEYSTRUC * pArg = (PUBLICKEYSTRUC *)pvArg;

    //  Begin processing
    printf("The argument passed is a structure.\n");
    printf("BLOB type= %x   ", pArg->bType);
    printf("Version= %x\n", pArg->bVersion);
    printf("Algorithm= %x\n\n", pArg->aiKeyAlg);
    return TRUE;
} // end callback function.


//////////////////////////////////////////////////////////////////////////////////////////////////


void CreatingCertificateChain(void)
/*
Example C Program: Creating a Certificate Chain
05/31/2018

The following example creates and installs a nondefault certificate chain engine.
The engine is used to build certificate chains for each of the certificates in a certificate store.

This example illustrates the following tasks and CryptoAPI functions:

Preparing to create a nondefault certificate chain engine by declaring and initializing a CERT_CHAIN_ENGINE_CONFIG data structure.
Creating the search engine using CertCreateCertificateChainEngine.
Using CertOpenSystemStore to open the My system store.
Retrieving all of the certificates from the open store using CertEnumCertificatesInStore in a loop.
For each certificate in the open store, retrieving the subject name from the certificate using CertGetNameString.
Building a certificate chain for each certificate using CertGetCertificateChain.
Creating a duplicate of the certificate chain using CertDuplicateCertificateChain.
Using CertFreeCertificateChain to release each chain before the next chain is built.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-creating-a-certificate-chain
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.
    HCERTCHAINENGINE         hChainEngine;
    CERT_CHAIN_ENGINE_CONFIG ChainConfig;
    PCCERT_CHAIN_CONTEXT     pChainContext;
    PCCERT_CHAIN_CONTEXT     pDupContext;
    HCERTSTORE               hCertStore;
    PCCERT_CONTEXT           pCertContext = NULL;
    CERT_ENHKEY_USAGE        EnhkeyUsage;
    CERT_USAGE_MATCH         CertUsage;
    CERT_CHAIN_PARA          ChainPara;
    DWORD                    dwFlags = 0;
    LPWSTR                   pszNameString;

    // Initialize data structures.
    if (!(pszNameString = (LPWSTR)malloc(256)))
        MyHandleError("Memory allocation failed.");
    EnhkeyUsage.cUsageIdentifier = 0;
    EnhkeyUsage.rgpszUsageIdentifier = NULL;
    CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage = EnhkeyUsage;
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage = CertUsage;

    ChainConfig.cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG);
    ChainConfig.hRestrictedRoot = NULL;
    ChainConfig.hRestrictedTrust = NULL;
    ChainConfig.hRestrictedOther = NULL;
    ChainConfig.cAdditionalStore = 0;
    ChainConfig.rghAdditionalStore = NULL;
    ChainConfig.dwFlags = CERT_CHAIN_CACHE_END_CERT;
    ChainConfig.dwUrlRetrievalTimeout = 0;
    ChainConfig.MaximumCachedCertificates = 0;
    ChainConfig.CycleDetectionModulus = 0;

    // Create the nondefault certificate chain engine.
    if (CertCreateCertificateChainEngine(&ChainConfig, &hChainEngine)) {
        printf("A chain engine has been created.\n");
    } else {
        MyHandleError("The engine creation function failed.");
    }

    // Open the My system store.
    if (hCertStore = CertOpenSystemStore(NULL, L"MY")) {
        printf("The MY Store is open.\n");
    } else {
        MyHandleError("The MY system store did not open.");
    }

    // Loop through the certificates in the store, and create a chain for each.
    while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
        // Get and display the name of subject of the certificate.
        if (CertGetNameString(pCertContext,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              0,
                              NULL,
                              pszNameString,
                              128)) {
            printf("\nCertificate for %ls found.\n", pszNameString);
        } else {
            MyHandleError("CertGetName failed.");
        }

        // Build a chain using CertGetCertificateChain and the certificate retrieved.
        if (CertGetCertificateChain(
            NULL,                  // use the default chain engine
            pCertContext,          // pointer to the end certificate
            NULL,                  // use the default time
            NULL,                  // search no additional stores
            &ChainPara,            // use AND logic and enhanced key usage 
                                   //  as indicated in the ChainPara data structure
            dwFlags,
            NULL,                  // currently reserved
            &pChainContext))       // return a pointer to the chain created
        {
            printf("The chain has been created. \n");
        } else {
            MyHandleError("The chain could not be created.");
        }

        // Display some of the contents of the chain.
        printf("The size of the chain context is %d. \n", pChainContext->cbSize);
        printf("%d simple chains found.\n", pChainContext->cChain);
        printf("\nError status for the chain:\n");

        switch (pChainContext->TrustStatus.dwErrorStatus) {
        case CERT_TRUST_NO_ERROR:
            printf("No error found for this certificate or chain.\n");
            break;
        case CERT_TRUST_IS_NOT_TIME_VALID:
            printf("This certificate or one of the certificates in the "
                   "certificate chain is not time-valid.\n");
            break;
        case CERT_TRUST_IS_REVOKED:
            printf("Trust for this certificate or one of the certificates "
                   "in the certificate chain has been revoked.\n");
            break;
        case CERT_TRUST_IS_NOT_SIGNATURE_VALID:
            printf("The certificate or one of the certificates in the "
                   "certificate chain does not have a valid signature.\n");
            break;
        case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
            printf("The certificate or certificate chain is not valid in its proposed usage.\n");
            break;
        case CERT_TRUST_IS_UNTRUSTED_ROOT:
            printf("The certificate or certificate chain is based on an untrusted root.\n");
            break;
        case CERT_TRUST_REVOCATION_STATUS_UNKNOWN:
            printf("The revocation status of the certificate or one of the"
                   "certificates in the certificate chain is unknown.\n");
            break;
        case CERT_TRUST_IS_CYCLIC:
            printf("One of the certificates in the chain was issued by a "
                   "certification authority that the original certificate had certified.\n");
            break;
        case CERT_TRUST_IS_PARTIAL_CHAIN:
            printf("The certificate chain is not complete.\n");
            break;
        case CERT_TRUST_CTL_IS_NOT_TIME_VALID:
            printf("A CTL used to create this chain was not time-valid.\n");
            break;
        case CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID:
            printf("A CTL used to create this chain did not have a valid signature.\n");
            break;
        case CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE:
            printf("A CTL used to create this chain is not valid for this usage.\n");
        } // End switch

        printf("\nInfo status for the chain:\n");
        switch (pChainContext->TrustStatus.dwInfoStatus) {
        case 0:
            printf("No information status reported.\n");
            break;
        case CERT_TRUST_HAS_EXACT_MATCH_ISSUER:
            printf("An exact match issuer certificate has been found for this certificate.\n");
            break;
        case CERT_TRUST_HAS_KEY_MATCH_ISSUER:
            printf("A key match issuer certificate has been found for this certificate.\n");
            break;
        case CERT_TRUST_HAS_NAME_MATCH_ISSUER:
            printf("A name match issuer certificate has been found for this certificate.\n");
            break;
        case CERT_TRUST_IS_SELF_SIGNED:
            printf("This certificate is self-signed.\n");
            break;
        case CERT_TRUST_IS_COMPLEX_CHAIN:
            printf("The certificate chain created is a complex chain.\n");
            break;
        } // end switch

        // Duplicate the original chain.
        if (pDupContext = CertDuplicateCertificateChain(pChainContext)) {
            printf("Duplicated the chain.\n");
        } else {
            printf("Duplication failed.\n");
        }

        // Free both chains.
        CertFreeCertificateChain(pDupContext);
        printf("The duplicate chains is free.\n");
        CertFreeCertificateChain(pChainContext);
        printf("The Original chain is free.\n");
        printf("\nPress Enter to continue.");
        (void)getchar();
    } // end while loop 

    printf("\nThere are no more certificates in the store. \n");

    // Free the chain engine.
    CertFreeCertificateChainEngine(hChainEngine);
    printf("The chain engine has been released.\n");

    // Free memory for pszNameString.
    if (pszNameString)
        free(pszNameString);

    printf("The demo program ran to completion without error.\n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void MakingCertificateRequest(void)
/*
Example C Program: Making a Certificate Request
05/31/2018

The following example demonstrates the procedure outlined in the previous section.
This example creates a simple certificate request with one signer,
a single relative distinguished name (RDN) attribute, and no general attributes.

This example illustrates the following CryptoAPI functions:
CryptEncodeObject
CryptAcquireContext
CryptExportPublicKeyInfo
CryptSignAndEncodeCertificate

This example also uses the functions ByteToStr and MyHandleError.
Code for these functions is included with the sample.
General Purpose Functions lists code for these and other auxiliary functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-making-a-certificate-request
*/
{
    // Declare and initialize variables 

    // Declare and initialize a CERT_RDN_ATTR array.
    // In this code, only one array element is used.
    CERT_RDN_ATTR rgNameAttr[] = {
            (LPSTR)"2.5.4.3",                             // pszObjId 
            CERT_RDN_PRINTABLE_STRING,             // dwValueType
            (DWORD)strlen(CERT_SUBJECT_NAME),             // value.cbData
            (BYTE *)CERT_SUBJECT_NAME};             // value.pbData

    // Declare and initialize a CERT_RDN array.
    // In this code, only one array element is used.
    CERT_RDN rgRDN[] = {
             1,                 // rgRDN[0].cRDNAttr
             &rgNameAttr[0]};   // rgRDN[0].rgRDNAttr

    // Declare and initialize a CERT_NAME_INFO structure.
    CERT_NAME_INFO Name = {
               1,                  // Name.cRDN
               rgRDN};             // Name.rgRDN

    // Declare and initialize all other variables and structures.
    CERT_REQUEST_INFO  CertReqInfo;
    CERT_NAME_BLOB  SubjNameBlob;
    DWORD  cbNameEncoded;
    BYTE * pbNameEncoded;
    HCRYPTPROV  hCryptProv;
    DWORD  cbPublicKeyInfo;
    CERT_PUBLIC_KEY_INFO * pbPublicKeyInfo;
    DWORD  cbEncodedCertReqSize;
    CRYPT_OBJID_BLOB  Parameters;
    CRYPT_ALGORITHM_IDENTIFIER  SigAlg;
    BYTE * pbSignedEncodedCertReq;
    char * pSignedEncodedCertReqBlob;

    //    Begin processing.
    if (CryptEncodeObject(
        MY_ENCODING_TYPE,     // Encoding type
        X509_NAME,            // Structure type
        &Name,                // Address of CERT_NAME_INFO structure
        NULL,                 // pbEncoded
        &cbNameEncoded))      // pbEncoded size
    {
        printf("The first call to CryptEncodeObject succeeded. \n");
    } else {
        MyHandleError("The first call to CryptEncodeObject failed. \n"
                      "A public/private key pair may not exit in the container. \n");
    }

    //     Allocate memory for the encoded name.
    if (!(pbNameEncoded = (BYTE *)malloc(cbNameEncoded)))
        MyHandleError("The pbNamencoded malloc operation failed. \n");

    //  Call CryptEncodeObject to do the actual encoding of the name.
    if (CryptEncodeObject(
        MY_ENCODING_TYPE,    // Encoding type
        X509_NAME,           // Structure type
        &Name,               // Address of CERT_NAME_INFO structure
        pbNameEncoded,       // pbEncoded
        &cbNameEncoded))     // pbEncoded size
    {
        printf("The object is encoded. \n");
    } else {
        free(pbNameEncoded);
        MyHandleError("The second call to CryptEncodeObject failed. \n");
    }

    // Set the subject member of CertReqInfo to point to a CERT_NAME_INFO structure that 
    // has been initialized with the data from cbNameEncoded and pbNameEncoded.
    SubjNameBlob.cbData = cbNameEncoded;
    SubjNameBlob.pbData = pbNameEncoded;
    CertReqInfo.Subject = SubjNameBlob;

    // Generate custom information. This step is not implemented in this code.
    CertReqInfo.cAttribute = 0;
    CertReqInfo.rgAttribute = NULL;
    CertReqInfo.dwVersion = CERT_REQUEST_V1;

    //    Call CryptExportPublicKeyInfo to return an initialized　CERT_PUBLIC_KEY_INFO structure.
    //    First, get a cryptographic provider.
    if (CryptAcquireContext(
        &hCryptProv,        // Address for handle to be returned.
        NULL,               // Use the current user's logon name.
        NULL,               // Use the default provider.
        PROV_RSA_FULL,      // Need to both encrypt and sign.
        NULL))              // No flags needed.
    {
        printf("A cryptographic provider has been acquired. \n");
    } else {
        free(pbNameEncoded);
        MyHandleError("CryptAcquireContext failed. \n");
    }

    // Call CryptExportPublicKeyInfo to get the size of the returned information.
    if (CryptExportPublicKeyInfo(
        hCryptProv,            // Provider handle
        AT_SIGNATURE,          // Key spec
        MY_ENCODING_TYPE,      // Encoding type
        NULL,                  // pbPublicKeyInfo
        &cbPublicKeyInfo))     // Size of PublicKeyInfo
    {
        printf("The keyinfo structure is %d bytes. \n", cbPublicKeyInfo);
    } else {
        free(pbNameEncoded);
        MyHandleError("The first call to CryptExportPublickKeyInfo failed. \n"
                      "The probable cause is that \n"
                      "there is no key pair in the key container. \n");
    }

    // Allocate the necessary memory.
    if (pbPublicKeyInfo = (CERT_PUBLIC_KEY_INFO *)malloc(cbPublicKeyInfo)) {
        printf("Memory is allocated for the public key structure. \n");
    } else {
        free(pbNameEncoded);
        MyHandleError("Memory allocation failed. \n");
    }

    // Call CryptExportPublicKeyInfo to get pbPublicKeyInfo.
    if (CryptExportPublicKeyInfo(
        hCryptProv,            // Provider handle
        AT_SIGNATURE,          // Key spec
        MY_ENCODING_TYPE,      // Encoding type
        pbPublicKeyInfo,       // pbPublicKeyInfo
        &cbPublicKeyInfo))     // Size of PublicKeyInfo
    {
        printf("The key has been exported. \n");
    } else {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        MyHandleError("The second call to CryptExportPublicKeyInfo failed. \n");
    }

    // Set the SubjectPublicKeyInfo member of the 
    // CERT_REQUEST_INFO structure to point to the CERT_PUBLIC_KEY_INFO structure created.
    CertReqInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;

    memset(&Parameters, 0, sizeof(Parameters));
    SigAlg.pszObjId = (LPSTR)szOID_OIWSEC_sha1RSASign;
    SigAlg.Parameters = Parameters;

    // Call CryptSignAndEncodeCertificate to get the size of the
    // returned BLOB. The dwKeySpec argument should match the KeySpec
    // (AT_SIGNATURE or AT_KEYEXCHANGE) used to create the private key. 
    // Here, AT_KEYEXCHANGE is assumed.

    if (CryptSignAndEncodeCertificate(
        hCryptProv,                      // Crypto provider
        AT_KEYEXCHANGE,                  // Key spec
        MY_ENCODING_TYPE,                // Encoding type
        X509_CERT_REQUEST_TO_BE_SIGNED,  // Structure type
        &CertReqInfo,                    // Structure information
        &SigAlg,                         // Signature algorithm
        NULL,                            // Not used
        NULL,                            // pbSignedEncodedCertReq
        &cbEncodedCertReqSize))          // Size of certificate required
    {
        printf("The size of the encoded certificate is set. \n");
    } else {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        MyHandleError("First call to CryptSignandEncode failed. \n");
    }

    // Allocate memory for the encoded certificate request.
    if (pbSignedEncodedCertReq = (BYTE *)malloc(cbEncodedCertReqSize)) {
        printf("Memory has been allocated.\n");
    } else {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        MyHandleError("The malloc operation failed. \n");
    }

    // Call CryptSignAndEncodeCertificate to get the returned BLOB.
    if (CryptSignAndEncodeCertificate(
        hCryptProv,                     // Crypto provider
        AT_KEYEXCHANGE,                 // Key spec
        MY_ENCODING_TYPE,               // Encoding type
        X509_CERT_REQUEST_TO_BE_SIGNED, // Struct type
        &CertReqInfo,                   // Struct info        
        &SigAlg,                        // Signature algorithm
        NULL,                           // Not used
        pbSignedEncodedCertReq,         // Pointer
        &cbEncodedCertReqSize))         // Length of the message
    {
        printf("The message is encoded and signed. \n");
    } else {
        free(pbNameEncoded);
        free(pbPublicKeyInfo);
        free(pbSignedEncodedCertReq);
        MyHandleError("The second call to CryptSignAndEncode failed. \n");
    }

    // View the signed and encoded certificate request BLOB.
    pSignedEncodedCertReqBlob = new char[(cbEncodedCertReqSize * 2) + 1];

    // Call ByteToStr, one of the general purpose functions, to convert 
    // the byte BLOB to ASCII hexadecimal format. 
    ByteToStr(cbEncodedCertReqSize, pbSignedEncodedCertReq, pSignedEncodedCertReqBlob);

    // Print the string.
    printf("The string created is: \n");
    printf("%s\n", pSignedEncodedCertReqBlob);

    // Free memory.
    free(pbNameEncoded);
    free(pbPublicKeyInfo);
    free(pbSignedEncodedCertReq);
    CryptReleaseContext(hCryptProv, 0);

    printf("\nMemory freed. Program ran without error. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI ASN(void)
/*
Example C Program: ASN.1 Encoding and Decoding
05/31/2018

The following example shows using CryptEncodeObjectEx and CryptDecodeObjectEx.
This example can easily be modified to use CryptEncodeObject and CryptDecodeObject.

This example also uses a modified version of the function ByteToStr to print an Abstract Syntax Notation One (ASN.1) encoded series of octets.
It also uses MyHandleError.
Code for these functions is included with the sample.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-asn1-encoding-and-decoding
*/
{
    const char * Cert_Sub_Name = "Test User Name";//   Declare and initialize local variables.

    // Initialize a single RDN structure.
    CERT_RDN_ATTR rgNameAttr =
    {
       (LPSTR)szOID_COMMON_NAME,         // the OID
       CERT_RDN_PRINTABLE_STRING,        // type of string
       (DWORD)strlen(Cert_Sub_Name) + 1, // string length including the terminating null character
       (BYTE *)Cert_Sub_Name             // pointer to the string
    };

    // Declare and initialize a structure to include the array of RDN structures.
    CERT_RDN rgRDN[] =
    {
       1,               // the number of elements in the array
       &rgNameAttr      // pointer to the array
    };

    //  Declare and initialize a CERT_NAME_INFO structure that includes a CERT_RND.
    CERT_NAME_INFO CertName =
    {
        1,          // number of elements in the CERT_RND's array
        rgRDN
    };

    //  Declare additional variables.
    CERT_NAME_INFO * pDecodeName; // point variable to hold the address of the decoded buffer
    DWORD cbEncoded;              // variable to hold the length of the encoded string
    DWORD cbDecoded;              // variable to hold the length of the decoded buffer
    BYTE * pbEncoded;             // variable to hold a pointer to the encoded buffer
    BYTE * pbDecoded;             // variable to hold a pointer to the decoded buffer
    LPSTR sz;

    //    Allocate memory for a large buffer.
    if (sz = (char *)malloc(512)) {
        printf("Memory for sz allocated\n");
    } else {
        MyHandleError("Memory allocation failed.");
    }

    // Call CrypteEncodeObjectEx to get length to allocate for pbEncoded.
    if (CryptEncodeObjectEx(
        MY_TYPE,        // the encoding/decoding type
        X509_NAME,
        &CertName,
        0,
        NULL,
        NULL,
        &cbEncoded))    // fill in the length needed for the encoded buffer
    {
        printf("The number of bytes needed is %d \n", cbEncoded);
    } else {
        MyHandleError("The first call to the function failed.\n");
    }

    if (pbEncoded = (BYTE *)malloc(cbEncoded)) {
        printf("Memory for pvEncoded has been allocated.\n");
    } else {
        MyHandleError("Memory allocation failed.");
    }

    if (CryptEncodeObjectEx(MY_TYPE, X509_NAME, &CertName, 0, NULL, pbEncoded, &cbEncoded)) {
        ByteToStr(cbEncoded, pbEncoded, sz);
        printf("The Encoded octets are \n%s\n", sz);
    } else {
        MyHandleError("Encoding failed.");
    }

    // Decode the encoded buffer.

    //  Get the length needed for the decoded buffer.
    if (CryptDecodeObjectEx(
        MY_TYPE,
        X509_NAME,
        pbEncoded,     // the buffer to be decoded
        cbEncoded,
        CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        NULL,
        &cbDecoded)) {
        printf("The needed buffer length is %d\n", cbDecoded);
    } else {
        MyHandleError("The first decode pass failed.");
    }

    // Allocate memory for the decoded information.
    if (!(pbDecoded = (BYTE *)malloc(cbDecoded))) {
        MyHandleError("Decode buffer memory allocation failed.");
    }

    // Decode the encoded buffer.
    if (CryptDecodeObjectEx(
        MY_TYPE,
        X509_NAME,
        pbEncoded,     // the buffer to be decoded
        cbEncoded,
        CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        pbDecoded,
        &cbDecoded)) {
        pDecodeName = (CERT_NAME_INFO *)pbDecoded;
        printf("The cRDN is -> %d \n", pDecodeName->cRDN);
        printf("The OID is -> ");
        printf("%s\n", pDecodeName->rgRDN->rgRDNAttr->pszObjId);
        printf("The string is ->");
        printf(" %s\n", pDecodeName->rgRDN->rgRDNAttr->Value.pbData);
    } else {
        MyHandleError("Decode failed.");
    }

    // Clean up memory.

    if (sz)
        free(sz);
    if (pbEncoded)
        free(pbEncoded);
    if (pbDecoded)
        free(pbDecoded);

    printf("Processing completed without error.\n");
}


//  Define ByteToStr.
//void ByteToStr(DWORD cb, void * pv, LPSTR sz)
//    // Parameters passed are:
//    //    pv -- the Array of BYTES to be converted.
//    //    cb -- the number of BYTEs in the array.
//    //    sz -- a pointer to the string to be returned.
//{
//    //  Declare and initialize local variables.
//
//    BYTE * pb = (BYTE *)pv; // local pointer to a BYTE in the BYTE array
//    DWORD i;               // local loop counter
//    int b;                 // local variable
//
//    //  Ensure that sz is large enough to hold pv.
//    if (strlen(sz) < cb) {
//        MyHandleError("The array of bytes is too long for the "
//                      "allocated string.");
//    }
//
//    //  Begin processing loop.
//    for (i = 0; i < cb; i++) {
//        b = (*pb & 0xF0) >> 4;
//        *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
//        b = *pb & 0x0F;
//        *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
//        pb++;
//        *sz++ = ' ';
//    }
//    *sz++ = 0;
//}  // end of ByteToStr


//////////////////////////////////////////////////////////////////////////////////////////////////


void my_wait(const char * s)
// Copyright (C) Microsoft.  All rights reserved.
// Declare a wait function to be defined following main.
// Define the my_wait function.
{
    printf(s);
    (void)getchar();
}


static BOOL WINAPI EnumInfoCallback(PCCRYPT_OID_INFO pInfo, void * pvArg)
// Callback function to print information
// saved in each CRYPT_OID_INFO structure.
// This function counts the number of lines printed
// and does a wait for each new ground and after any four report groups are printed.
{
    static DWORD old_oid = 0;
    static int break_counter = 0;

    if (old_oid < pInfo->dwGroupId) {
        if (old_oid > 0) {
            my_wait("\n Begin new group. \n Hit enter to continue.");
            break_counter = 0;
        }
        old_oid = pInfo->dwGroupId;
        printf("\nNew Group ID %d \n", old_oid);
    }
    printf("  OID: %s\n  Name: %S\n", pInfo->pszOID, pInfo->pwszName);

    // If there is an AlgId, print it.
    if (pInfo->Algid > 0) {
        printf("  Algorithm ID hexadecimal %x \n\n", pInfo->Algid);
    } else {
        printf("\n");
    }

    if (++break_counter > 4) {
        break_counter = 0;
        my_wait("\n   Hit enter to continue.");
    }

    return TRUE;
}


void UsingCertOIDToAlgIdAndCertCompareIntegerBlob()
/*
Example C Program: Using CertOIDToAlgId and CertCompareIntegerBlob
05/31/2018

The following example demonstrates using the CertOIDToAlgId and CertCompareIntegerBlob functions.

First, all available OIDs are enumerated using CryptEnumOIDInfo.
Code used with this function also demonstrates the use of a callback function.
The callback function demonstrates break logic to pause between each OID group and after presenting information on a set number of OIDs.

Second, three object identifier (OID) strings are converted into DWORD algorithm identifier integers using CertOIDToAlgId.
The code also demonstrates that all OID strings do not have related algorithm identifiers.

Finally, the example demonstrates comparing integer BLOBs.
This example demonstrates the truncation of leading 0x00's from positive numbers and leading 0xFF's from negative numbers.

It also shows that integers are compared as though they are stored in little-endian form with the most significant digits on the right.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-certoidtoalgid-and-certcompareintegerblob
*/
{
    // Note: Integer BLOBs are treated as if they are stored in little-endian form with the 
    // most significant digits on the right. Truncation is therefore from the right.
    // Integer BLOBs are also assumed to be signed numbers in two's compliment form.
    // For negative numbers, 0xFFs on the right are truncated.
    // For positive numbers, 0x00s on the right are truncated.

    // Declare and initialize local variables.
    DWORD Alg_Id;
    CRYPT_INTEGER_BLOB  Int1, Int2;
    BYTE BLOB1data[4] = {0x88, 0xFF, 0xFF, 0xFF};
    BYTE BLOB2data[2] = {0x88, 0xFF};
    BYTE BLOB3data[4] = {0x01, 0x00, 0x00, 0x00};
    BYTE BLOB4data[2] = {0x01, 0x00};
    BYTE BLOB5data[4] = {0x01, 0x00, 0x01, 0x00};

    // Enumerate the algorithm OIDs available.
    // Note that this one call to the function with dwGroupId set to 0 lists all OIDs in all groups. 
    if (!(CryptEnumOIDInfo(
        0,                  // use 0 to enumerate the OIDs in all groups
        0,                  // dwFlags
        NULL,               // no additional parameters are to be passed to the callback function.
        EnumInfoCallback    // name of the callback function to be called for each OID enumerated.
    ))) {
        printf("Enumeration of algorithm OIDs did not complete.\n");
    }

    // Use CertOIDToAlgId() to convert the szOID_RSA_RC4 Object Identifier string to an algorithm identifier.
    if (Alg_Id = CertOIDToAlgId(szOID_RSA_RC4)) {
        // Print the Alg_Id returned in hex.
        printf("szOID_RSA_RC4 / %s is %x\n\n", szOID_RSA_RC4, Alg_Id);
    } else {
        printf("No ALG_ID for OID szOID_RSA_RC4 / %s.\n", szOID_RSA_RC4);
    }

    // Convert the szOID_RSA_RC2CBC Object Identifier string to an algorithm identifier.
    if (Alg_Id = CertOIDToAlgId(szOID_RSA_RC2CBC)) {
        // Print the Alg_Id returned in hex.
        printf("szOID_RSA_RC2CBC / %s is %x\n\n", szOID_RSA_RC2CBC, Alg_Id);
    } else {
        printf("No ALG_ID for szOID_RSA_RC2CBC / %s.\n", szOID_RSA_RC2CBC);
    }

    // Convert the szOID_RSA_RC5_CBCPad Object Identifier string to an algorithm identifier.
    if (Alg_Id = CertOIDToAlgId(szOID_RSA_RC5_CBCPad)) {
        // Print the Alg_Id returned in hex.
        printf("szOID_RSA_RC5_CBCPad / %s is %x\n", szOID_RSA_RC5_CBCPad, Alg_Id);
    } else {
        printf("No ALG_ID for szOID_RSA_RC5_CBCPad: %s.\n", szOID_RSA_RC5_CBCPad);
    }

    // Initialize Int1 and Int2. 
    Int1.pbData = (BYTE *)&BLOB1data;
    Int2.pbData = (BYTE *)&BLOB2data;

    // Set the cbData members so that only the leftmost two bytes of the 
    // first are compared to the leftmost bytes of the second.
    Int1.cbData = 4;  // sizeof(BLOB1data);
    Int2.cbData = 2;  // sizeof(BLOB2data);
    if (CertCompareIntegerBlob(&Int1, &Int2)) {
        printf("The first two bytes of the BLOBs are identical.\n");
    } else {
        printf("The first two bytes BLOBs are not identical.\n");
    }

    // Reset the cbData members to compare only 1 byte from each.
    Int1.cbData = 1;
    Int2.cbData = 1;
    if (CertCompareIntegerBlob(&Int1, &Int2)) {
        printf("The BLOBs of different length are identical.\n");
    } else {
        printf("The BLOBs of different length are not identical.\n");
    }

    // Reset to check the positive numbers.
    Int1.cbData = 4;
    Int2.cbData = 2;
    Int1.pbData = BLOB3data;
    Int2.pbData = BLOB4data;
    if (CertCompareIntegerBlob(&Int1, &Int2)) {
        printf("The BLOBs 3 and 4 are identical.\n");
    } else {
        printf("The BLOBs 3 and 4 are not identical.\n");
    }

    // Compare BLOB 1 and BLOB 3.
    Int1.cbData = 4;
    Int2.cbData = 4;
    Int1.pbData = BLOB1data;
    Int2.pbData = BLOB3data;
    if (CertCompareIntegerBlob(&Int1, &Int2)) {
        printf("BLOBs 1 and 3 are identical.\n");
    } else {
        printf("BLOBs 1 and 3 are not identical.\n");
    }

    // Compare BLOB 3 and BLOB 5.
    Int1.cbData = 4;
    Int2.cbData = 4;
    Int1.pbData = BLOB5data;
    Int2.pbData = BLOB3data;
    if (CertCompareIntegerBlob(&Int1, &Int2)) {
        printf("BLOBs 5 and 3 are identical.\n");
    } else {
        printf("BLOBs 5 and 3 are not identical.\n");
    }

    // Compare the first two bytes of BLOB 3 and BLOB 5.
    Int1.cbData = 2;
    Int2.cbData = 2;
    Int1.pbData = BLOB5data;
    Int2.pbData = BLOB3data;
    if (CertCompareIntegerBlob(&Int1, &Int2)) {
        printf("The first two bytes of BLOBs 5 and 3 are identical.\n");
    } else {
        printf("The first two bytes of BLOBs 5 and 3 not identical.\n");
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Example of verifying the embedded signature of a PE file by using the WinVerifyTrust function.


BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
/*
Example C Program: Verifying the Signature of a PE File
05/31/2018

The WinVerifyTrust API can be used to verify the signature of a portable executable file.

The following example shows how to use the WinVerifyTrust API to verify the signature of a signed portable executable file.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file

注意：此函数不能检测签名信息不在自身，而在别处（如CAT）的文件。
*/
{
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;// Use default code signing EKU.    
    WinTrustData.pSIPClientData = NULL;// No data to pass to SIP.    
    WinTrustData.dwUIChoice = WTD_UI_NONE;// Disable WVT UI.    
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;// No revocation checking.    
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;// Verify an embedded signature on a file.    
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;// Verify action.    
    WinTrustData.hWVTStateData = NULL;// Verification sets this value.    
    WinTrustData.pwszURLReference = NULL;// Not used.

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of installing applications.
    WinTrustData.dwUIContext = 0;

    WinTrustData.pFile = &FileData;// Set pFile.

    // WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
    switch (lStatus) {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.
            - Trusted publisher without any verification errors.
            - UI was disabled in dwUIChoice. No publisher or time stamp chain errors.
            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed subject.
        */
        wprintf_s(L"The file \"%s\" is signed and the signature was verified.\n", pwszSourceFile);
        break;
    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError) {
            // The file was not signed.
            wprintf_s(L"The file \"%s\" is not signed.\n", pwszSourceFile);
        } else {
            // The signature was not valid or there was an error opening the file.
            wprintf_s(L"An unknown error occurred trying to "
                      L"verify the signature of the \"%s\" file.\n", pwszSourceFile);
        }

        break;
    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        wprintf_s(L"The signature is present, but specifically disallowed.\n");
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        wprintf_s(L"The signature is present, but not trusted.\n");
        break;
    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature, publisher or time stamp errors.
        */
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
                  L"representing the subject or the publisher wasn't "
                  L"explicitly trusted by the admin and admin policy "
                  L"has disabled user trust. No signature, publisher "
                  L"or timestamp errors.\n");
        break;
    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n", lStatus);
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return true;
}


EXTERN_C
__declspec(dllexport)
LONG WINAPI VerifyEmbeddedSignatureEx(LPCWSTR pwszSourceFile)
/*
Example C Program: Verifying the Signature of a PE File
05/31/2018

The WinVerifyTrust API can be used to verify the signature of a portable executable file.

The following example shows how to use the WinVerifyTrust API to verify the signature of a signed portable executable file.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file

注意：此函数不能检测签名信息不在自身，而在别处（如CAT）的文件。
*/
{
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;// Use default code signing EKU.    
    WinTrustData.pSIPClientData = NULL;// No data to pass to SIP.    
    WinTrustData.dwUIChoice = WTD_UI_NONE;// Disable WVT UI.    
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;// No revocation checking.    
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;// Verify an embedded signature on a file.    
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;// Verify action.    
    WinTrustData.hWVTStateData = NULL;// Verification sets this value.    
    WinTrustData.pwszURLReference = NULL;// Not used.

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of installing applications.
    WinTrustData.dwUIContext = 0;

    WinTrustData.pFile = &FileData;// Set pFile.

    // WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
    switch (lStatus) {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.
            - Trusted publisher without any verification errors.
            - UI was disabled in dwUIChoice. No publisher or time stamp chain errors.
            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed subject.
        */
        wprintf_s(L"The file \"%s\" is signed and the signature was verified.\n", pwszSourceFile);
        break;
    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError) {
            // The file was not signed.
            wprintf_s(L"The file \"%s\" is not signed.\n", pwszSourceFile);
        } else {
            // The signature was not valid or there was an error opening the file.
            wprintf_s(L"An unknown error occurred trying to "
                      L"verify the signature of the \"%s\" file.\n", pwszSourceFile);
        }

        break;
    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        wprintf_s(L"The signature is present, but specifically disallowed.\n");
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        wprintf_s(L"The signature is present, but not trusted.\n");
        break;
    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature, publisher or time stamp errors.
        */
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
                  L"representing the subject or the publisher wasn't "
                  L"explicitly trusted by the admin and admin policy "
                  L"has disabled user trust. No signature, publisher "
                  L"or timestamp errors.\n");
        break;
    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n", lStatus);
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    LONG lStatus2 = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return lStatus;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Example of how to modify the access restrictions for the default key container.


// Local function prototypes.
BOOL GetHandleToCSP(HCRYPTPROV *, LPCTSTR, DWORD);
BOOL GenPrivateKeys(HCRYPTPROV, DWORD);
BOOL GetHandleToCSP(HCRYPTPROV *, LPCTSTR, DWORD);
SECURITY_DESCRIPTOR * GetProvSecurityDesc(HCRYPTPROV);
BOOL ModifyDacl(HCRYPTPROV hProv);


int ModifyingKeyContainerAccess(int argc, _TCHAR * argv[])
/*
Modifying Key Container Access
05/31/2018

The default key container that is created by CryptoAPI does not allow access to the keys from the LocalService or NetworkService accounts.
This can be corrected programmatically by using the CryptSetProvParam function to modify the PP_KEYSET_SEC_DESCR parameter.

The following example shows how to use the CryptSetProvParam function to modify the PP_KEYSET_SEC_DESCR to allow access to a key container to the LocalService or NetworkService accounts.

 Note
The following code is given as a tool and should only be used if absolutely necessary.
You should only have to run this code once on each computer to allow access to the keys.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/modifying-key-container-access
*/
{
    HCRYPTKEY hKey = 0;
    HCRYPTPROV hProv = 0;

    if (!GetHandleToCSP(&hProv, MY_CONTAINER_NAME, CRYPT_MACHINE_KEYSET)) {
        printf("OpenCtxHandle failed.\n");
        goto CommonReturn;
    }
    printf("Acquired a context.\n");

    if (!GenPrivateKeys(hProv, 0)) {
        printf("GenPrivateKeys failed.\n");
        goto CommonReturn;
    }
    printf("Generated Private keys.\n");

    // Change the ACLs to allow read for local service.
    if (!ModifyDacl(hProv)) {
        printf("ModifyDacl failed.\n");
        goto CommonReturn;
    }
    printf("Modified default ACLs on container.\n");

CommonReturn:
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }

    return 0;
}


BOOL GetHandleToCSP(HCRYPTPROV * phProv, LPCTSTR pszContainerName, DWORD dwProvFlag)
/*
Acquire a handle to the cryptographic service provider.
*/
{
    if (!CryptAcquireContext(phProv, pszContainerName, MS_STRONG_PROV, PROV_RSA_FULL, dwProvFlag)) {
        if (NTE_BAD_KEYSET == GetLastError() || NTE_EXISTS == GetLastError()) {
            if (!CryptAcquireContext(
                phProv,
                pszContainerName,
                MS_STRONG_PROV,
                PROV_RSA_FULL,
                CRYPT_NEWKEYSET | dwProvFlag)) {
                printf("Error 0x%08x.\n", GetLastError());
                return FALSE;
            }
        } else {
            printf(" Error in CryptAcquireContext 0x%08x.\n", GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}


BOOL GenPrivateKeys(HCRYPTPROV hProv, DWORD dwflagkey)
/*
Generates a signature and a key exchange key.
*/
{
    BOOL fRet = FALSE;
    HCRYPTKEY hSigKey = 0;
    HCRYPTKEY hExchKey = 0;

    // Generate the signature key.
    if (!CryptGenKey(hProv, AT_SIGNATURE, dwflagkey, &hSigKey)) {
        printf("CryptGenKey failed with 0x%08x.\n", GetLastError());
        goto CommonReturn;
    }

    // Generate the key exchange key.
    if (!CryptGenKey(hProv, AT_KEYEXCHANGE, dwflagkey, &hExchKey)) {
        printf("CryptGenKey failed with 0x%08x.\n", GetLastError());
        goto CommonReturn;
    }

    fRet = TRUE;

CommonReturn:

    if (hSigKey) {
        CryptDestroyKey(hSigKey);
    }

    if (hExchKey) {
        CryptDestroyKey(hExchKey);
    }

    return fRet;
}


SECURITY_DESCRIPTOR * GetProvSecurityDesc(HCRYPTPROV hProv)
/*
Retrieves the security descriptor for the specified provider.
*/
{
    SECURITY_DESCRIPTOR * psd = NULL;
    unsigned long ulSize = 0;

    // Get the size of the security descriptor.
    if (!CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, 0, &ulSize, DACL_SECURITY_INFORMATION)) {
        int ret = GetLastError();
        if (ret != ERROR_INSUFFICIENT_BUFFER) {
            fprintf(stderr, "Error getting file security DACL: %d.\n", ret);
            goto Error_Occurred;
        }
    }

    // Allocate the memory for the security descriptor.
    psd = (SECURITY_DESCRIPTOR *)LocalAlloc(LPTR, ulSize);
    if (!psd) {
        fprintf(stderr, "Out of memory for security descriptor!\n");
        goto Error_Occurred;
    }

    // Retrieve the security descriptor.
    if (!CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, (BYTE *)psd, &ulSize, DACL_SECURITY_INFORMATION)) {
        fprintf(stderr, "CryptGetProvParam failed with 0x%08x.\n", GetLastError());
        goto Error_Occurred;
    }

    return psd;

Error_Occurred:
    // An error occurred, so if memory was allocated, free it.
    if (psd) {
        LocalFree(psd);
        psd = NULL;
    }

    return NULL;
}


ACL * GetDacl(SECURITY_DESCRIPTOR * psd)
/*
Retrieves the DACL from the specified security descriptor.
*/
{
    ACL * pACL = NULL;
    int defaulted = 0;
    int present = 0;

    if (!psd) {
        return NULL;
    }

    if (!GetSecurityDescriptorDacl(psd, &present, &pACL, &defaulted)) {
        fprintf(stderr, "Error getting DACL from security descriptor: %d.\n", GetLastError());
        return 0;
    }

    if (!present) {
        fprintf(stderr, "Security descriptor has no DACL present.\n");
        return 0;
    }

    return pACL;
}


BOOL ModifyDacl(HCRYPTPROV hProv)
/*
Modifies the DACL for the key storage folder for the specified provider.
*/
{
    PSID pSid = NULL;
    DWORD cbSid = 0;
    LPTSTR szDomainName = NULL;
    DWORD cbDomainName = 0;
    SID_NAME_USE SidType;
    EXPLICIT_ACCESS ea[1] = {0};
    DWORD dwRes = 0;
    SECURITY_DESCRIPTOR * pCurrentSD = NULL;
    PSECURITY_DESCRIPTOR pNewSD = NULL;
    PACL pCurrentDACL = NULL;
    PACL pNewACL = NULL;

    while (!LookupAccountName(NULL,
                              TEXT("LocalService"),
                              pSid,
                              &cbSid,
                              szDomainName,
                              &cbDomainName,
                              &SidType)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pSid = LocalAlloc(LPTR, cbSid);
            szDomainName = (LPTSTR)LocalAlloc(LPTR, (cbDomainName * sizeof(TCHAR)));
            if (pSid == NULL || szDomainName == NULL) {
                printf("LocalAlloc failed.\n");
                goto CommonReturn;
            }
        } else {
            printf("LookupAccountName error: %d.\n", GetLastError());
            goto CommonReturn;
        }
    }

    //Get existing ACLs for the file. 
    pCurrentSD = GetProvSecurityDesc(hProv);
    if (!pCurrentSD) {
        printf("Unable to retrieve SD.\n");
        goto CommonReturn;
    }

    pCurrentDACL = GetDacl(pCurrentSD);
    if (!pCurrentDACL) {
        printf("Unable to retrieve DACL.\n");
        goto CommonReturn;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow the user read access to the container.
    ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = FILE_READ_DATA;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPTSTR)pSid;

    // Create a new ACL that contains the new ACEs as well as the old ones.
    dwRes = SetEntriesInAcl(1, ea, pCurrentDACL, &pNewACL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetEntriesInAcl error: %u.\n", GetLastError());
        goto CommonReturn;
    }

    // Initialize a security descriptor.  
    pNewSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (NULL == pNewSD) {
        printf("LocalAlloc error: %u.\n", GetLastError());
        goto CommonReturn;
    }

    if (!InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION)) {
        printf("InitializeSecurityDescriptor error: %u.\n", GetLastError());
        goto CommonReturn;
    }

    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(pNewSD, TRUE, pNewACL, FALSE)) {
        printf("SetSecurityDescriptorDacl error: %u.\n", GetLastError());
        goto CommonReturn;
    }

    // Set the new security descriptor.
    if (!CryptSetProvParam(hProv, PP_KEYSET_SEC_DESCR, (BYTE *)pNewSD, DACL_SECURITY_INFORMATION)) {
        printf("CryptSetProvParam error: 0x%08x.\n", GetLastError());
        goto CommonReturn;
    }

CommonReturn:

    if (pSid) {
        LocalFree(pSid);
    }

    if (pNewACL) {
        LocalFree(pNewACL);
    }

    if (pNewSD) {
        LocalFree(pNewSD);
    }

    if (pCurrentSD) {
        LocalFree(pCurrentSD);
    }

    return 1;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info);
BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME * st);
BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext);
BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO * pCounterSignerInfo);


EXTERN_C
__declspec(dllexport)
int WINAPI GetInformationFromAuthenticodeSignedExecutables(int argc, TCHAR * argv[])
/*
Get information from Authenticode Signed Executables

This article shows how to get information from Authenticode Signed Executables.

Original product version:   Windows SDK
Original KB number:   323809

Summary
You can use the WinVerifyTrust() API to verify an Authenticode signed executable.

Although a signature is verified, a program may also have to do the following:

Determine the details of the certificate that signed the executable.
Determine the date and time that the file was time stamped.
Retrieve the URL link associated with the file.
Retrieve the timestamp certificate.
This article demonstrates how to use CryptQueryObject() API to retrieve detailed information from an Authenticode signed executable.

More information
Authenticode signatures are PKCS7-based, therefore you can use CryptQueryObject and
other Crypto API functions to retrieve the PKCS7 signature and to decode the PKCS7 attributes.

The following sample c code demonstrates how to use these APIs.

http://support.microsoft.com/kb/323809/zh-cn
您可以使用 WinVerifyTrust() API 以验证验证码签名可执行文件。

虽然签名进行验证，程序可能还需要执行下列：
确定签名可执行文件的证书的详细信息。
确定日期和时间戳操作的文件时间。
检索与文件相关联的 URL 链接。
检索时间戳的证书。
本文演示如何使用 CryptQueryObject() API 检索验证码签名可执行文件的详细的信息。
Collapse image更多信息
验证码签名都是基于 PKCS7 的因此您可以使用 CryptQueryObject 和其他加密 API 函数以检索 PKCS7 签名并解码 PKCS7 属性。

https://docs.microsoft.com/en-US/troubleshoot/windows/win32/get-information-authenticode-signed-executables
*/

/*
从 Authenticode 签名可执行文件中获取信息(How To Get Information from Authenticode Signed Executables)
2020/10/26

本文介绍如何从验证码签名可执行文件中获取信息。

原始产品版本：   Windows SDK
原始 KB 数：   323809

摘要
您可以使用 WinVerifyTrust() API 验证验证码签名的可执行文件。

虽然验证了签名，但程序可能还必须执行以下操作：

确定签名了可执行文件的证书的详细信息。
确定文件时间戳的日期和时间。
检索与文件关联的 URL 链接。
检索时间戳证书。
本文演示如何使用 CryptQueryObject() API 检索验证码签名可执行文件中的详细信息。

更多信息
验证码签名是基于 PKCS7 的，因此您可以使用 CryptQueryObject 和其他 Crypto API 函数检索 PKCS7 签名并对属性进行解码 PKCS7 。

下面的示例 c 代码演示如何使用这些 Api。

https://docs.microsoft.com/zh-CN/troubleshoot/windows/win32/get-information-authenticode-signed-executables
*/
/*
此代码检测的文件是带签名的文件，如：带签名的PE，或者CAT文件，但不能是签名信息在CAT的PE文件。
*/
{
    WCHAR szFileName[MAX_PATH];
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;
    SPROG_PUBLISHERINFO ProgPubInfo;
    SYSTEMTIME st;

    if (argc != 2) {
        _tprintf(_T("Usage: SignedFileInfo <filename>\n"));
        return 0;
    }

    ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
    __try {
# ifdef UNICODE
        (void)lstrcpynW(szFileName, argv[1], MAX_PATH);
#else
        if (mbstowcs(szFileName, argv[1], MAX_PATH) == -1) {
            printf("Unable to convert to unicode.\n");
            __leave;
        }
#endif

        // Get message handle and store handle from the signed file.
        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                   szFileName,
                                   CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                   CERT_QUERY_FORMAT_FLAG_BINARY,
                                   0,
                                   &dwEncoding,
                                   &dwContentType,
                                   &dwFormatType,
                                   &hStore,
                                   &hMsg,
                                   NULL);
        if (!fResult) {
            _tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
            __leave;
    }

        // Get signer information size.
        fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
        if (!fResult) {
            _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }

        // Allocate memory for signer information.
        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo) {
            _tprintf(_T("Unable to allocate memory for Signer Info.\n"));
            __leave;
        }

        // Get Signer Information.
        fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);
        if (!fResult) {
            _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }

        // Get program name and publisher information from signer info structure.
        if (GetProgAndPublisherInfo(pSignerInfo, &ProgPubInfo)) {
            if (ProgPubInfo.lpszProgramName != NULL) {
                wprintf(L"Program Name : %s\n", ProgPubInfo.lpszProgramName);
            }

            if (ProgPubInfo.lpszPublisherLink != NULL) {
                wprintf(L"Publisher Link : %s\n", ProgPubInfo.lpszPublisherLink);
            }

            if (ProgPubInfo.lpszMoreInfoLink != NULL) {
                wprintf(L"MoreInfo Link : %s\n", ProgPubInfo.lpszMoreInfoLink);
            }
        }

        _tprintf(_T("\n"));

        // Search for the signer certificate in the temporary certificate store.
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;
        pCertContext = CertFindCertificateInStore(hStore,
                                                  ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_CERT,
                                                  (PVOID)&CertInfo,
                                                  NULL);
        if (!pCertContext) {
            _tprintf(_T("CertFindCertificateInStore failed with %x\n"), GetLastError());
            __leave;
        }

        // Print Signer certificate information.
        _tprintf(_T("Signer Certificate:\n\n"));
        PrintCertificateInfo(pCertContext);
        _tprintf(_T("\n"));

        // Get the timestamp certificate signerinfo structure.
        if (GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo)) {
            // Search for Timestamp certificate in the temporary certificate store.
            CertInfo.Issuer = pCounterSignerInfo->Issuer;
            CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;
            pCertContext = CertFindCertificateInStore(hStore,
                                                      ENCODING,
                                                      0,
                                                      CERT_FIND_SUBJECT_CERT,
                                                      (PVOID)&CertInfo,
                                                      NULL);
            if (!pCertContext) {
                _tprintf(_T("CertFindCertificateInStore failed with %x\n"), GetLastError());
                __leave;
            }

            // Print timestamp certificate information.
            _tprintf(_T("TimeStamp Certificate:\n\n"));
            PrintCertificateInfo(pCertContext);
            _tprintf(_T("\n"));

            // Find Date of timestamp.
            if (GetDateOfTimeStamp(pCounterSignerInfo, &st)) {
                _tprintf(_T("Date of TimeStamp : %02d/%02d/%04d %02d:%02d\n"),
                         st.wMonth,
                         st.wDay,
                         st.wYear,
                         st.wHour,
                         st.wMinute);
            }
            _tprintf(_T("\n"));
        }
} __finally {
        // Clean up.
        if (ProgPubInfo.lpszProgramName != NULL)
            LocalFree(ProgPubInfo.lpszProgramName);
        if (ProgPubInfo.lpszPublisherLink != NULL)
            LocalFree(ProgPubInfo.lpszPublisherLink);
        if (ProgPubInfo.lpszMoreInfoLink != NULL)
            LocalFree(ProgPubInfo.lpszMoreInfoLink);

        if (pSignerInfo != NULL) LocalFree(pSignerInfo);
        if (pCounterSignerInfo != NULL) LocalFree(pCounterSignerInfo);
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
        if (hStore != NULL) CertCloseStore(hStore, 0);
        if (hMsg != NULL) CryptMsgClose(hMsg);
    }

    return 0;
}


BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext)
{
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData;

    __try {
        // Print Serial Number.
        _tprintf(_T("Serial Number: "));
        dwData = pCertContext->pCertInfo->SerialNumber.cbData;
        for (DWORD n = 0; n < dwData; n++) {
            _tprintf(_T("%02x "), pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
        }
        _tprintf(_T("\n"));

        // Get Issuer name size.
        if (!(dwData = CertGetNameString(pCertContext,
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         CERT_NAME_ISSUER_FLAG,
                                         NULL,
                                         NULL,
                                         0))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for Issuer name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for issuer name.\n"));
            __leave;
        }

        // Get Issuer name.
        if (!(CertGetNameString(pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG,
                                NULL,
                                szName,
                                dwData))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // print Issuer name.
        _tprintf(_T("Issuer Name: %s\n"), szName);
        LocalFree(szName);
        szName = NULL;

        // Get Subject name size.
        if (!(dwData = CertGetNameString(pCertContext,
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         0,
                                         NULL,
                                         NULL,
                                         0))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for subject name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for subject name.\n"));
            __leave;
        }

        // Get subject name.
        if (!(CertGetNameString(pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                NULL,
                                szName,
                                dwData))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        _tprintf(_T("Subject Name: %s\n"), szName);// Print Subject Name.

        fReturn = TRUE;
    } __finally {
        if (szName != NULL) LocalFree(szName);
    }

    return fReturn;
}


LPWSTR AllocateAndCopyWideString(LPCWSTR inputString)
{
    LPWSTR outputString = NULL;

    outputString = (LPWSTR)LocalAlloc(LPTR, (wcslen(inputString) + 1) * sizeof(WCHAR));
    if (outputString != NULL) {
        lstrcpyW(outputString, inputString);
    }

    return outputString;
}


BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info)
{
    BOOL fReturn = FALSE;
    PSPC_SP_OPUS_INFO OpusInfo = NULL;
    DWORD dwData;
    BOOL fResult;

    __try {
        // Loop through authenticated attributes and find SPC_SP_OPUS_INFO_OBJID OID.
        for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++) {
            if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0) {
                // Get Size of SPC_SP_OPUS_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                                            SPC_SP_OPUS_INFO_OBJID,
                                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                                            0,
                                            NULL,
                                            &dwData);
                if (!fResult) {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                    __leave;
                }

                // Allocate memory for SPC_SP_OPUS_INFO structure.
                OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
                if (!OpusInfo) {
                    _tprintf(_T("Unable to allocate memory for Publisher Info.\n"));
                    __leave;
                }

                // Decode and get SPC_SP_OPUS_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                                            SPC_SP_OPUS_INFO_OBJID,
                                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                                            pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                                            0,
                                            OpusInfo,
                                            &dwData);
                if (!fResult) {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                    __leave;
                }

                // Fill in Program Name if present.
                if (OpusInfo->pwszProgramName) {
                    Info->lpszProgramName = AllocateAndCopyWideString(OpusInfo->pwszProgramName);
                } else
                    Info->lpszProgramName = NULL;

                // Fill in Publisher Information if present.
                if (OpusInfo->pPublisherInfo) {
                    switch (OpusInfo->pPublisherInfo->dwLinkChoice) {
                    case SPC_URL_LINK_CHOICE:
                        Info->lpszPublisherLink = AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
                        break;
                    case SPC_FILE_LINK_CHOICE:
                        Info->lpszPublisherLink = AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
                        break;
                    default:
                        Info->lpszPublisherLink = NULL;
                        break;
                    }
                } else {
                    Info->lpszPublisherLink = NULL;
                }

                // Fill in More Info if present.
                if (OpusInfo->pMoreInfo) {
                    switch (OpusInfo->pMoreInfo->dwLinkChoice) {
                    case SPC_URL_LINK_CHOICE:
                        Info->lpszMoreInfoLink = AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
                        break;
                    case SPC_FILE_LINK_CHOICE:
                        Info->lpszMoreInfoLink = AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
                        break;
                    default:
                        Info->lpszMoreInfoLink = NULL;
                        break;
                    }
                } else {
                    Info->lpszMoreInfoLink = NULL;
                }

                fReturn = TRUE;

                break; // Break from for loop.
            } // lstrcmp SPC_SP_OPUS_INFO_OBJID 
        } // for 
    } __finally {
        if (OpusInfo != NULL) LocalFree(OpusInfo);
    }

    return fReturn;
}


BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME * st)
{
    BOOL fResult;
    FILETIME lft, ft;
    DWORD dwData;
    BOOL fReturn = FALSE;

    // Loop through authenticated attributes and find szOID_RSA_signingTime OID.
    for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++) {
        if (lstrcmpA(szOID_RSA_signingTime, pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0) {
            // Decode and get FILETIME structure.
            dwData = sizeof(ft);
            fResult = CryptDecodeObject(ENCODING,
                                        szOID_RSA_signingTime,
                                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                                        0,
                                        (PVOID)&ft,
                                        &dwData);
            if (!fResult) {
                _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                break;
            }

            // Convert to local time.
            FileTimeToLocalFileTime(&ft, &lft);
            FileTimeToSystemTime(&lft, st);

            fReturn = TRUE;

            break; // Break from for loop.
        } //lstrcmp szOID_RSA_signingTime
    } // for 

    return fReturn;
}


BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO * pCounterSignerInfo)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fReturn = FALSE;
    BOOL fResult;
    DWORD dwSize;

    __try {
        *pCounterSignerInfo = NULL;

        // Loop through unathenticated attributes for szOID_RSA_counterSign OID.
        for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++) {
            if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0) {
                // Get size of CMSG_SIGNER_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                                            PKCS7_SIGNER_INFO,
                                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                                            0,
                                            NULL,
                                            &dwSize);
                if (!fResult) {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                    __leave;
                }

                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (!*pCounterSignerInfo) {
                    _tprintf(_T("Unable to allocate memory for timestamp info.\n"));
                    __leave;
                }

                // Decode and get CMSG_SIGNER_INFO structure for timestamp certificate.
                fResult = CryptDecodeObject(ENCODING,
                                            PKCS7_SIGNER_INFO,
                                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                                            0,
                                            (PVOID)*pCounterSignerInfo,
                                            &dwSize);
                if (!fResult) {
                    _tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
                    __leave;
                }

                fReturn = TRUE;

                break; // Break from for loop.
            }
        }
    } __finally {// Clean up.        
        if (pCertContext != NULL)
            CertFreeCertificateContext(pCertContext);
    }

    return fReturn;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved


void PrintUsage(_In_ PCWSTR fileName)
{
    wprintf(L"%s [-p] <-c | -e> file\n", fileName);
    wprintf(L"Flags:\n");
    wprintf(L"  -p: Use signature policy of the current os (szOID_CERT_STRONG_SIGN_OS_CURRENT)\n");
    wprintf(L"  -c: Search for the file in system catalogs\n");
    wprintf(L"  -e: Verify embedded file signature\n");
}


EXTERN_C
__declspec(dllexport)
DWORD WINAPI VerifyEmbeddedSignatures(_In_ PCWSTR FileName,
                                      _In_ HANDLE FileHandle,
                                      _In_ bool UseStrongSigPolicy
)
/*
Verifies all embedded signatures of a file

功能：找出签名在自身，且排除主签名的，所有的辅助签名的信息。
*/
{
    DWORD Error = ERROR_SUCCESS;
    bool WintrustCalled = false;
    GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WintrustData = {};
    WINTRUST_FILE_INFO FileInfo = {};
    WINTRUST_SIGNATURE_SETTINGS SignatureSettings = {};
    CERT_STRONG_SIGN_PARA StrongSigPolicy = {};

    // Setup data structures for calling WinVerifyTrust
    WintrustData.cbStruct = sizeof(WINTRUST_DATA);
    WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WintrustData.dwUIChoice = WTD_UI_NONE;
    WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO_);
    FileInfo.hFile = FileHandle;
    FileInfo.pcwszFilePath = FileName;
    WintrustData.pFile = &FileInfo;

    // First verify the primary signature (index 0) to determine how many secondary signatures
    // are present. We use WSS_VERIFY_SPECIFIC and dwIndex to do this, also setting 
    // WSS_GET_SECONDARY_SIG_COUNT to have the number of secondary signatures returned.
    SignatureSettings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
    SignatureSettings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
    SignatureSettings.dwIndex = 0;
    WintrustData.pSignatureSettings = &SignatureSettings;

    if (UseStrongSigPolicy != false) {
        StrongSigPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
        StrongSigPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
        StrongSigPolicy.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
        WintrustData.pSignatureSettings->pCryptoPolicy = &StrongSigPolicy;
    }

    wprintf(L"Verifying primary signature... ");
    Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
    WintrustCalled = true;
    if (Error != ERROR_SUCCESS) {
        PrintError(Error);
        goto Cleanup;
    }

    wprintf(L"Success!\n");

    wprintf(L"Found %d secondary signatures\n", WintrustData.pSignatureSettings->cSecondarySigs);

    // Now attempt to verify all secondary signatures that were found
    for (DWORD x = 1; x <= WintrustData.pSignatureSettings->cSecondarySigs; x++) {
        wprintf(L"Verify secondary signature at index %d... ", x);

        // Need to clear the previous state data from the last call to WinVerifyTrust
        WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
        if (Error != ERROR_SUCCESS) {
            WintrustCalled = false;//No need to call WinVerifyTrust again
            PrintError(Error);
            goto Cleanup;
        }

        WintrustData.hWVTStateData = NULL;

        // Caller must reset dwStateAction as it may have been changed during the last call
        WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        WintrustData.pSignatureSettings->dwIndex = x;
        Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
        if (Error != ERROR_SUCCESS) {
            PrintError(Error);
            goto Cleanup;
        }

        wprintf(L"Success!\n");
    }

Cleanup:

    // Caller must call WinVerifyTrust with WTD_STATEACTION_CLOSE to free memory allocate by WinVerifyTrust
    if (WintrustCalled != false) {
        WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
    }

    return Error;
}


DWORD WINAPI VerifyCatalogSignature(_In_ HANDLE FileHandle, _In_ bool UseStrongSigPolicy)
/*
Looks up a file by hash in the system catalogs.

功能：找出一个文件的对应的CatalogFile，如果这个文件有CatalogFile的话。
      注意一个文件可能对应多个CatalogFile。

注释：对于没签名和签名在自身的文件，这个代码检测不出。
*/
{
    DWORD Error = ERROR_SUCCESS;
    bool Found = false;
    HCATADMIN CatAdminHandle = NULL;
    HCATINFO CatInfoHandle = NULL;
    DWORD HashLength = 0;
    PBYTE HashData = NULL;
    CERT_STRONG_SIGN_PARA SigningPolicy = {};

    if (UseStrongSigPolicy != false) {
        SigningPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
        SigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
        SigningPolicy.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
        if (!CryptCATAdminAcquireContext2(&CatAdminHandle,
                                          NULL,
                                          BCRYPT_SHA256_ALGORITHM,
                                          &SigningPolicy,
                                          0)) {
            Error = GetLastError();
            goto Cleanup;
        }
    } else {
        if (!CryptCATAdminAcquireContext2(&CatAdminHandle,
                                          NULL,
                                          BCRYPT_SHA256_ALGORITHM,
                                          NULL,
                                          0)) {
            Error = GetLastError();
            goto Cleanup;
        }
    }

    // Get size of hash to be used
    if (!CryptCATAdminCalcHashFromFileHandle2(CatAdminHandle,
                                              FileHandle,
                                              &HashLength,
                                              NULL,
                                              NULL)) {
        Error = GetLastError();
        goto Cleanup;
    }

    HashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
    if (HashData == NULL) {
        Error = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    // Generate hash for a give file
    if (!CryptCATAdminCalcHashFromFileHandle2(CatAdminHandle,
                                              FileHandle,
                                              &HashLength,
                                              HashData,
                                              NULL)) {
        Error = GetLastError();
        goto Cleanup;
    }

    // Find the first catalog containing this hash
    CatInfoHandle = NULL;
    CatInfoHandle = CryptCATAdminEnumCatalogFromHash(CatAdminHandle,
                                                     HashData,
                                                     HashLength,
                                                     0,
                                                     &CatInfoHandle);
    while (CatInfoHandle != NULL) {
        CATALOG_INFO catalogInfo = {};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        Found = true;

        if (!CryptCATCatalogInfoFromContext(CatInfoHandle, &catalogInfo, 0)) {
            Error = GetLastError();
            break;
        }

        wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);

        // Look for the next catalog containing the file's hash
        CatInfoHandle = CryptCATAdminEnumCatalogFromHash(CatAdminHandle,
                                                         HashData,
                                                         HashLength,
                                                         0,
                                                         &CatInfoHandle);
    }

    if (Found != true) {
        wprintf(L"Hash was not found in any catalogs.\n");
    }

Cleanup:

    if (CatAdminHandle != NULL) {
        if (CatInfoHandle != NULL) {
            CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatInfoHandle, 0);
        }

        CryptCATAdminReleaseContext(CatAdminHandle, 0);
    }

    if (HashData != NULL) {
        HeapFree(GetProcessHeap(), 0, HashData);
    }

    return Error;
}


DWORD WINAPI VerifyCatalogSignature(_In_ PCWSTR FileName,
                                    _In_ bool UseStrongSigPolicy,
                                    _In_ list<wstring> & CatalogFile
)
/*
Looks up a file by hash in the system catalogs.

功能：找出一个文件的对应的CatalogFile，如果这个文件有CatalogFile的话。
      注意一个文件可能对应多个CatalogFile。

注释：对于没签名和签名在自身的文件，这个代码检测不出。
*/
{
    DWORD Error = ERROR_SUCCESS;
    bool Found = false;
    HCATADMIN CatAdminHandle = NULL;
    HCATINFO CatInfoHandle = NULL;
    DWORD HashLength = 0;
    PBYTE HashData = NULL;
    CERT_STRONG_SIGN_PARA SigningPolicy = {};
    HANDLE FileHandle = INVALID_HANDLE_VALUE;

    FileHandle = CreateFileW(FileName,
                             GENERIC_READ,
                             FILE_SHARE_READ,
                             NULL,
                             OPEN_EXISTING,
                             0,
                             NULL);
    if (FileHandle == INVALID_HANDLE_VALUE) {
        Error = GetLastError();
        goto Cleanup;
    }

    if (UseStrongSigPolicy != false) {
        SigningPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
        SigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
        SigningPolicy.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
        if (!CryptCATAdminAcquireContext2(&CatAdminHandle,
                                          NULL,
                                          BCRYPT_SHA256_ALGORITHM,
                                          &SigningPolicy,
                                          0)) {
            Error = GetLastError();
            goto Cleanup;
        }
    } else {
        if (!CryptCATAdminAcquireContext2(&CatAdminHandle,
                                          NULL,
                                          BCRYPT_SHA256_ALGORITHM,
                                          NULL,
                                          0)) {
            Error = GetLastError();
            goto Cleanup;
        }
    }

    // Get size of hash to be used
    if (!CryptCATAdminCalcHashFromFileHandle2(CatAdminHandle,
                                              FileHandle,
                                              &HashLength,
                                              NULL,
                                              NULL)) {
        Error = GetLastError();
        goto Cleanup;
    }

    HashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
    if (HashData == NULL) {
        Error = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    // Generate hash for a give file
    if (!CryptCATAdminCalcHashFromFileHandle2(CatAdminHandle, 
                                              FileHandle,
                                              &HashLength,
                                              HashData,
                                              NULL)) {
        Error = GetLastError();
        goto Cleanup;
    }

    // Find the first catalog containing this hash
    CatInfoHandle = NULL;
    CatInfoHandle = CryptCATAdminEnumCatalogFromHash(CatAdminHandle,
                                                     HashData,
                                                     HashLength,
                                                     0,
                                                     &CatInfoHandle);
    while (CatInfoHandle != NULL) {
        CATALOG_INFO catalogInfo = {};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        Found = true;

        if (!CryptCATCatalogInfoFromContext(CatInfoHandle, &catalogInfo, 0)) {
            Error = GetLastError();
            break;
        }

        wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);
        CatalogFile.push_back(catalogInfo.wszCatalogFile);

        // Look for the next catalog containing the file's hash
        CatInfoHandle = CryptCATAdminEnumCatalogFromHash(CatAdminHandle,
                                                         HashData,
                                                         HashLength,
                                                         0,
                                                         &CatInfoHandle);
    }

    if (Found != true) {
        wprintf(L"Hash was not found in any catalogs.\n");
    }

Cleanup:

    if (CatAdminHandle != NULL) {
        if (CatInfoHandle != NULL) {
            CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatInfoHandle, 0);
        }

        CryptCATAdminReleaseContext(CatAdminHandle, 0);
    }

    if (HashData != NULL) {
        HeapFree(GetProcessHeap(), 0, HashData);
    }

    if (FileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(FileHandle);
    }

    return Error;
}


EXTERN_C
__declspec(dllexport)
int WINAPI SignatureVerification(_In_ unsigned int argc, _In_reads_(argc) PCWSTR wargv[])
/*
摘自：
Windows-classic-samples\Samples\Security\CodeSigning
同时，这个工程也叫：WinVerifyTrust signature verification sample
*/
{
    DWORD Error = ERROR_SUCCESS;
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    DWORD ArgStart = 1;
    bool UseStrongSigPolicy = false;

    if (argc < 3 || argc > 4) {
        PrintUsage(wargv[0]);
        Error = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (_wcsicmp(wargv[ArgStart], L"-p") == 0) {
        UseStrongSigPolicy = true;
        ArgStart++;
    }

    if (ArgStart + 1 >= argc) {
        PrintUsage(wargv[0]);
        Error = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    if ((wcslen(wargv[ArgStart]) != 2) ||
        ((_wcsicmp(wargv[ArgStart], L"-c") != 0) && (_wcsicmp(wargv[ArgStart], L"-e") != 0))) {
        PrintUsage(wargv[0]);
        Error = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    FileHandle = CreateFileW(wargv[ArgStart + 1],
                             GENERIC_READ,
                             FILE_SHARE_READ,
                             NULL,
                             OPEN_EXISTING,
                             0,
                             NULL);
    if (FileHandle == INVALID_HANDLE_VALUE) {
        Error = GetLastError();
        PrintError(Error);
        goto Cleanup;
    }

    if (_wcsicmp(wargv[ArgStart], L"-c") == 0) {
        Error = VerifyCatalogSignature(FileHandle, UseStrongSigPolicy);
    } else if (_wcsicmp(wargv[ArgStart], L"-e") == 0) {
        Error = VerifyEmbeddedSignatures(wargv[ArgStart + 1], FileHandle, UseStrongSigPolicy);
    } else {
        PrintUsage(wargv[0]);
        Error = ERROR_INVALID_PARAMETER;
    }

Cleanup:

    if (FileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(FileHandle);
    }

    return Error;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//EXTERN_C
//__declspec(dllexport)
bool WINAPI VerifySignature(_In_ PCWSTR FileName, _Inout_ list<wstring> & SignatureFile)
/*
功能：统用的防范的校验签名的函数。

思路：
1.先获取签名信息所在的文件（有的是在自身，有的在CAT）。再获取具体的签名信息。
2.先检查自身是否有签名，如果有获取信息并返回，再检查是否有CatalogFile。

这里采用方案2.

注意：一个文件可以有多个CatalogFile，一个签名文件可以有多个签名。
*/
{
    LONG lStatus = VerifyEmbeddedSignatureEx(FileName);
    if (ERROR_SUCCESS == lStatus) {
        SignatureFile.push_back(FileName);
        wprintf(L"Embedded Signature.\n");
        return true;
    }

    DWORD Error = VerifyCatalogSignature(FileName, false, SignatureFile);
    if (ERROR_SUCCESS == Error) {
        wprintf(L"Catalog Signature.\n");
        return true;
    }

    wprintf(L"No Signature.\n");
    return false;
}


//////////////////////////////////////////////////////////////////////////////////////////////////



#define SmartCard TRUE


#ifdef SmartCard


#define MAX_CERT_SIMPLE_NAME_STR 1000


int SmartCardLogon(TCHAR * pPIN);


int SmartCardLogonTest(int argc, _TCHAR * argv[])
{
    if (argc != 2) {
        _tprintf(_T("\nUSAGE: %ls PIN \n"), argv[0]);
        _tprintf(_T("Example: \"%ls 1234 \"\n\n"), argv[0]);
        return 1;
    }

    SmartCardLogon(argv[1]);

    return 0;
}


int SmartCardLogon(TCHAR * pPIN)
/*
How to read a certificate from a Smart Card and add it to the system store
2010/05/28

The basic high level steps to read a certificate from a Smart Card and add it to the system store are:

1. Establish a Smart Card context using SCardEstablishContext.
2. Display the select card dialog box.
3. Get the card type provider name.
4. Acquire the CSP context.
5. Get the user key.
6. Get the key parameters and create a certificate context in memory.
7. Open the system store.
8. Use the API CertAddCertificateContextToStore to add in the certificate context to the store.

https://docs.microsoft.com/zh-cn/archive/blogs/winsdk/how-to-read-a-certificate-from-a-smart-card-and-add-it-to-the-system-store
*/
{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCERTSTORE hStoreHandle = NULL;
    BOOL fStatus;
    BOOL fSave = FALSE;
    SCARDCONTEXT hSC;
    OPENCARDNAME_EX dlgStruct;
    WCHAR szReader[256];
    WCHAR szCard[256];
    WCHAR pProviderName[256];
    LONG lReturn;
    DWORD lStatus;
    DWORD cchProvider = 256;
    DWORD dwCertLen;
    DWORD dwLogonCertsCount = 0;
    //DWORD dwHashLen = CERT_HASH_LENGTH;
    BYTE * pCertBlob;
    PCCERT_CONTEXT pCertContext = NULL;
    LPTSTR szMarshaledCred = NULL;

    // Establish a context.

    // It will be assigned to the structure's hSCardContext field.
    lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC);
    if (SCARD_S_SUCCESS != lReturn) {
        _tprintf(_T("Failed SCardEstablishContext\n"));
        return 1;
    }

    // Initialize the structure.
    memset(&dlgStruct, 0, sizeof(dlgStruct));
    dlgStruct.dwStructSize = sizeof(dlgStruct);
    dlgStruct.hSCardContext = hSC;
    dlgStruct.dwFlags = SC_DLG_FORCE_UI;
    dlgStruct.lpstrRdr = szReader;
    dlgStruct.nMaxRdr = 256;
    dlgStruct.lpstrCard = szCard;
    dlgStruct.nMaxCard = 256;
    dlgStruct.lpstrTitle = L"My Select Card Title";

    // Display the select card dialog box.
    lReturn = SCardUIDlgSelectCard(&dlgStruct);
    if (SCARD_S_SUCCESS != lReturn) {
        _tprintf(_T("Failed SCardUIDlgSelectCard - %x\n"), lReturn);
    } else {
        _tprintf(_T("Reader: %ls\nCard: %ls\n"), szReader, szCard);
    }

    lStatus = SCardGetCardTypeProviderName(
        dlgStruct.hSCardContext, // SCARDCONTEXT hContext,
        dlgStruct.lpstrCard, // LPCTSTR szCardName,
        SCARD_PROVIDER_CSP, // DWORD dwProviderId,
        pProviderName, // LPTSTR szProvider,
        &cchProvider // LPDWORD* pcchProvider
    );

    _tprintf(_T("SCardGetCardTypeProviderName returned: %u (a value of 0 is success)\n"), lStatus);

    if (SCARD_S_SUCCESS != lReturn) {
        _tprintf(_T("Failed SCardGetCardTypeProviderName - %u\n"), lStatus);
    } else {
        _tprintf(_T("Provider name: %ls.\n"), pProviderName);
    }

    fStatus = CryptAcquireContext(
        &hProv, // HCRYPTPROV* phProv,
        NULL, // LPCTSTR pszContainer,
        pProviderName, // LPCTSTR pszProvider,
        PROV_RSA_FULL, // DWORD dwProvType,
        0 // DWORD dwFlags
    );
    if (!fStatus) {
        _tprintf(_T("CryptAcquireContext failed: 0x%x\n"), GetLastError());
        return 1;
    } else {
        _tprintf(_T("CryptAcquireContext succeeded.\n"));
    }

    fStatus = CryptGetUserKey(
        hProv, // HCRYPTPROV hProv,
        AT_KEYEXCHANGE, // DWORD dwKeySpec,
        &hKey // HCRYPTKEY* phUserKey
    );
    if (!fStatus) {
        _tprintf(_T("CryptGetUserKey failed: 0x%x\n"), GetLastError());
        return 1;
    } else {
        _tprintf(_T("CryptGetUserKey succeeded.\n"));
    }

    dwCertLen = 0;
    fStatus = CryptGetKeyParam(
        hKey, // HCRYPTKEY hKey,
        KP_CERTIFICATE, // DWORD dwParam,
        NULL, // BYTE* pbData,
        &dwCertLen, // DWORD* pdwDataLen,
        0 // DWORD dwFlags
    );
    if (!fStatus) {
        _tprintf(_T("CryptGetUserKey failed: 0x%x\n"), GetLastError());
        return 1;
    } else {
        _tprintf(_T("CryptGetUserKey succeeded.\n"));
    }

    _tprintf(_T("dwCertLen: %u\n"), dwCertLen);

    pCertBlob = (BYTE *)malloc(dwCertLen);
    fStatus = CryptGetKeyParam(
        hKey, // HCRYPTKEY hKey,
        KP_CERTIFICATE, // DWORD dwParam,
        pCertBlob, // BYTE* pbData,
        &dwCertLen, // DWORD* pdwDataLen,
        0 // DWORD dwFlags
    );
    if (!fStatus) {
        _tprintf(_T("CryptGetUserKey failed: 0x%x\n"), GetLastError());
        return 1;
    } else {
        _tprintf(_T("CryptGetUserKey succeeded.\n"));
    }

    pCertContext = CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                                pCertBlob,
                                                dwCertLen);
    if (pCertContext) {
        // Add the certificate to the MY store for the current user.
        // Open Root cert store in users profile

        _tprintf(_T("CertOpenStore... "));

        hStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     0,
                                     0,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"My");
        if (!hStoreHandle) {
            _tprintf(_T("CertOpenStore failed: 0x%x\n"), GetLastError());
            return 0;
        }

        // Add self-signed cert to the store
        _tprintf(_T("CertAddCertificateContextToStore... "));

        if (!CertAddCertificateContextToStore(hStoreHandle,
                                              pCertContext,
                                              CERT_STORE_ADD_REPLACE_EXISTING,
                                              0)) {
            _tprintf(_T("CertAddCertificateContextToStore failed: 0x%x\n"), GetLastError());
            return 0;
        }

        CertFreeCertificateContext(pCertContext);
    }

    return 0;
}


#endif // SmartCard


//////////////////////////////////////////////////////////////////////////////////////////////////


void RemoveCertificate(_In_ LPCWSTR FileName)
{
    HANDLE hfile = INVALID_HANDLE_VALUE;

    __try {
        hfile = CreateFile(FileName,
                           FILE_READ_DATA | FILE_WRITE_DATA,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hfile == INVALID_HANDLE_VALUE) {
            int x = GetLastError();
            __leave;
        }

        DWORD CertificateCount = 0;
        DWORD Indices[9] = {0};
        DWORD  IndexCount = ARRAYSIZE(Indices);
        BOOL ret = ImageEnumerateCertificates(hfile,
                                              CERT_SECTION_TYPE_ANY,
                                              &CertificateCount,
                                              Indices,
                                              IndexCount);
        if (!ret) {
            int x = GetLastError();
            __leave;
        }

        for (DWORD i = 0; i < CertificateCount; i++) {
            ret = ImageRemoveCertificate(hfile, i);
            if (!ret) {
                int x = GetLastError();
            }
        }
    } __finally {
        if (INVALID_HANDLE_VALUE != hfile) {
            CloseHandle(hfile);
        }
    }
}


BOOL WINAPI DigestFunction(DIGEST_HANDLE refdata, PBYTE pData, DWORD dwLength)
//这个会被调用多次。
{

    return true;
}


void ImageGetCertificateTest(_In_ LPCWSTR FileName)
{
    HANDLE hfile = INVALID_HANDLE_VALUE;
    LPWIN_CERTIFICATE buffer = NULL;

    __try {
        hfile = CreateFile(FileName,
                           FILE_READ_DATA | FILE_WRITE_DATA,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hfile == INVALID_HANDLE_VALUE) {
            int x = GetLastError();
            __leave;
        }

        DWORD CertificateCount = 0;
        DWORD Indices[9] = {0};
        DWORD  IndexCount = ARRAYSIZE(Indices);
        BOOL ret = ImageEnumerateCertificates(hfile,
                                              CERT_SECTION_TYPE_ANY,
                                              &CertificateCount,
                                              Indices,
                                              IndexCount);
        if (!ret) {
            int x = GetLastError();
            __leave;
        }

        for (DWORD i = 0; i < CertificateCount; i++) {
            WIN_CERTIFICATE Certificateheader = {0};
            ret = ImageGetCertificateHeader(hfile, i, &Certificateheader);
            if (!ret) {
                int x = GetLastError();
            }

            WIN_CERTIFICATE Certificate = {0};
            DWORD RequiredLength = sizeof(WIN_CERTIFICATE);
            ret = ImageGetCertificateData(hfile, i, &Certificate, &RequiredLength);
            if (!ret) {
                int x = GetLastError();
            }

            buffer = (LPWIN_CERTIFICATE)HeapAlloc(GetProcessHeap(), 0, RequiredLength);
            _ASSERTE(buffer);

            ret = ImageGetCertificateData(hfile, i, buffer, &RequiredLength);
            _ASSERTE(ret);

            DIGEST_HANDLE DigestHandle = NULL;
            ret = ImageGetDigestStream(hfile, i, DigestFunction, DigestHandle);
            if (!ret) {
                int x = GetLastError();
            }

            HeapFree(GetProcessHeap(), 0, buffer);
        }
    } __finally {
        if (INVALID_HANDLE_VALUE != hfile) {
            CloseHandle(hfile);
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
