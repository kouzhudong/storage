#include "pch.h"
#include "Certificate.h"


#pragma warning(disable:28182)
#pragma warning(disable:28183)
#pragma warning(disable:6387)
#pragma warning(disable:6001)
#pragma warning(disable:4477)
#pragma warning(disable:4313)
#pragma warning(disable:4473)
#pragma warning(disable:6064)
#pragma warning(disable:6067)
#pragma warning(disable:6273)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Using Certificates
2018/05/31

The following sections deal with creating and using certificates,
including decoding information from certificate data structures,
changing and encoding data into certificates,
and working with certificate properties:

Using a CERT_INFO Data Structure
Example C Program: Listing the Certificates in a Store
Example C Program: Deleting Certificates from a Certificate Store
Example C Program: Certificate Store Operations
Example C Program: Serializing Certificates
Example C Program: Getting and Setting Certificate Properties
Example C Program: Converting Names from Certificates to ASN.1 and Back
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


void ListingCertificatesInStore(void)
/*
Example C Program: Listing the Certificates in a Store
2018/05/31

输入的参数可以有：
CA      对应certmgr->中间证书颁发机构->证书
MY      对应certmgr->个人->证书
ROOT    对应certmgr->受信任的根证书颁发机构->证书
Trust   对应certmgr->企业信任->证书

浏览器的相应的选项可能有所减少。

The following example code lists all of the certificates in a system certificate store and
the name of the subject and all of the certificate context properties of each of those certificates.
The example gets the name of the certificate store from the user and thus can be used to list the contents of any system certificate store.
In addition, this example shows the use of two new UI functions, one that displays a certificate and the other,
UI that allows the user to select a certificate from a list of the certificates in a store.

This example code illustrates the following tasks and CryptoAPI functions:

Opening a system store using CertOpenSystemStore.
In a loop, enumerating all of the certificates in the open store using CertEnumCertificatesInStore.
Displaying a certificate using CryptUIDlgViewContext.
Getting the name of the certificate's subject using CertGetNameString.
In a loop, using CertEnumCertificateContextProperties to get the property identifiers of all of the properties associated with the certificate.
Using CertGetCertificateContextProperty to get each of the properties.
Displaying a list of certificates in a store and allowing a user to select one of them using CryptUIDlgSelectCertificateFromStore.
Closing the certificate store using CertCloseStore.
This example uses the function MyHandleError. Code for this function is included with the sample.

Code for this and other auxiliary functions is also listed under General Purpose Functions.

The following example shows enumerating and displaying the certificates in a store.
To compile this example, you must configure your compiler to use a multiple-byte character set.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-listing-the-certificates-in-a-store
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // This program lists all of the certificates in a system certificate
    // store and all of the property identifier numbers of those certificates. 
    // It also demonstrates the use of two UI functions.
    // One, CryptUIDlgSelectCertificateFromStore, 
    // displays the certificates in a store and allows the user to select one of them, 
    // The other, CryptUIDlgViewContext, displays the contents of a single certificate.

    // Declare and initialize variables.
    HCERTSTORE       hCertStore;
    PCCERT_CONTEXT   pCertContext = NULL;
    char pszNameString[256];
    char pszStoreName[256];
    void * pvData;
    DWORD            cbData = 0;
    DWORD            dwPropId = 0;
    // Zero must be used on the first
    // call to the function. After that, the last returned property identifier is passed.

//  Begin processing and Get the name of the system certificate store 
//  to be enumerated. Output here is to stderr so that the program  
//  can be run from the command line and stdout can be redirected to a file.
    fprintf(stderr, "Please enter the store name:");
    gets_s(pszStoreName, sizeof(pszStoreName));
    fprintf(stderr, "The store name is %s.\n", pszStoreName);

    // Open a system certificate store.
    if (hCertStore = CertOpenSystemStoreA(NULL, pszStoreName)) {
        fprintf(stderr, "The %s store has been opened. \n", pszStoreName);
    } else {
        // If the store was not opened, exit to an error routine.
        MyHandleError("The store was not opened.");
    }

    // Use CertEnumCertificatesInStore to get the certificates 
    // from the open store. pCertContext must be reset to
    // NULL to retrieve the first certificate in the store.

    // pCertContext = NULL;

    while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
        // A certificate was retrieved. Continue.
        //  Display the certificate.
        if (CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pCertContext, NULL, NULL, 0, NULL)) {
            //     printf("OK\n");
        } else {
            MyHandleError("UI failed.");
        }

        if (CertGetNameStringA(pCertContext,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               pszNameString,
                               128)) {
            printf("\nCertificate for %s \n", pszNameString);
        } else
            fprintf(stderr, "CertGetName failed. \n");

        // Loop to find all of the property identifiers for the specified certificate.  
        // The loop continues until CertEnumCertificateContextProperties returns zero.

        while (dwPropId = CertEnumCertificateContextProperties(
            pCertContext, // The context whose properties are to be listed.
            dwPropId))    // Number of the last property found.  
                          // This must be zero to find the first property identifier.
        {
            // When the loop is executed, a property identifier has been found.
            // Print the property number.

            printf("Property # %d found->", dwPropId);

            // Indicate the kind of property found.
            switch (dwPropId) {
            case CERT_FRIENDLY_NAME_PROP_ID:
            {
                printf("Display name: ");
                break;
            }
            case CERT_SIGNATURE_HASH_PROP_ID:
            {
                printf("Signature hash identifier ");
                break;
            }
            case CERT_KEY_PROV_HANDLE_PROP_ID:
            {
                printf("KEY PROVE HANDLE");
                break;
            }
            case CERT_KEY_PROV_INFO_PROP_ID:
            {
                printf("KEY PROV INFO PROP ID ");
                break;
            }
            case CERT_SHA1_HASH_PROP_ID:
            {
                printf("SHA1 HASH identifier");
                break;
            }
            case CERT_MD5_HASH_PROP_ID:
            {
                printf("md5 hash identifier ");
                break;
            }
            case CERT_KEY_CONTEXT_PROP_ID:
            {
                printf("KEY CONTEXT PROP identifier");
                break;
            }
            case CERT_KEY_SPEC_PROP_ID:
            {
                printf("KEY SPEC PROP identifier");
                break;
            }
            case CERT_ENHKEY_USAGE_PROP_ID:
            {
                printf("ENHKEY USAGE PROP identifier");
                break;
            }
            case CERT_NEXT_UPDATE_LOCATION_PROP_ID:
            {
                printf("NEXT UPDATE LOCATION PROP identifier");
                break;
            }
            case CERT_PVK_FILE_PROP_ID:
            {
                printf("PVK FILE PROP identifier ");
                break;
            }
            case CERT_DESCRIPTION_PROP_ID:
            {
                printf("DESCRIPTION PROP identifier ");
                break;
            }
            case CERT_ACCESS_STATE_PROP_ID:
            {
                printf("ACCESS STATE PROP identifier ");
                break;
            }
            case CERT_SMART_CARD_DATA_PROP_ID:
            {
                printf("SMART_CARD DATA PROP identifier ");
                break;
            }
            case CERT_EFS_PROP_ID:
            {
                printf("EFS PROP identifier ");
                break;
            }
            case CERT_FORTEZZA_DATA_PROP_ID:
            {
                printf("FORTEZZA DATA PROP identifier ");
                break;
            }
            case CERT_ARCHIVED_PROP_ID:
            {
                printf("ARCHIVED PROP identifier ");
                break;
            }
            case CERT_KEY_IDENTIFIER_PROP_ID:
            {
                printf("KEY IDENTIFIER PROP identifier ");
                break;
            }
            case CERT_AUTO_ENROLL_PROP_ID:
            {
                printf("AUTO ENROLL identifier. ");
                break;
            }
            } // End switch.

         // Retrieve information on the property by first getting the property size. 
         // For more information, see CertGetCertificateContextProperty.
            if (CertGetCertificateContextProperty(pCertContext, dwPropId, NULL, &cbData)) {
                //  Continue.
            } else {
                // If the first call to the function failed, exit to an error routine.
                MyHandleError("Call #1 to GetCertContextProperty failed.");
            }

            // The call succeeded. Use the size to allocate memory for the property.
            if (pvData = (void *)malloc(cbData)) {
                // Memory is allocated. Continue.
            } else {
                // If memory allocation failed, exit to an error routine.
                MyHandleError("Memory allocation failed.");
            }

            // Allocation succeeded. Retrieve the property data.
            if (CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, &cbData)) {
                // The data has been retrieved. Continue.
            } else {
                // If an error occurred in the second call, exit to an error routine.
                MyHandleError("Call #2 failed.");
            }

            printf("The Property Content is %d \n", pvData);// Show the results.            
            free(pvData);// Free the certificate context property memory.
        }  // End inner while.
    } // End outer while.

    // Select a new certificate by using the user interface.
    if (!(pCertContext = CryptUIDlgSelectCertificateFromStore(
        hCertStore,
        NULL,
        NULL,
        NULL,
        CRYPTUI_SELECT_LOCATION_COLUMN,
        0,
        NULL))) {
        MyHandleError("Select UI failed.");
    }

    // Clean up.
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);
    printf("The function completed successfully. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void DeletingCertificatesfromCertificateStore(void)
/*
Example C Program: Deleting Certificates from a Certificate Store
2018/05/31

The following example lists the certificates in a system certificate store,
displaying the name of the subject of each certificate,
and it allows the user to choose to delete any certificates from the store.
The example gets the name of the certificate store from the user and
thus can be used to maintain the contents of any system certificate store.

This example illustrates the following tasks and CryptoAPI functions:

Opening a system certificate store using CertOpenSystemStore.
Listing the certificates in a certificate store using CertEnumCertificatesInStore.
Getting the name of the subject of a certificate using CertGetNameString.
Comparing the name of the subject of the certificate with the name of the issuer of the certificate using CertCompareCertificateName.
Checking to determine whether the public key of the current certificate matches the public key of a previous certificate using CertComparePublicKeyInfo.
Duplicating a pointer to a certificate context using CertDuplicateCertificateContext.
Comparing the CERT_INFO members of each certificate using CertCompareCertificate.
Deleting a certificate from a store using CertDeleteCertificateFromStore.
Closing a certificate store using CertCloseStore.
This example gets the name of a system certificate store from the user,
opens that store, and goes through the certificates in that store.
For each certificate, the name of the certificate's subject is displayed and
the user is given an option to delete that certificate.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-deleting-certificates-from-a-certificate-store
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.
    HANDLE          hStoreHandle;
    PCCERT_CONTEXT  pCertContext = NULL;
    PCCERT_CONTEXT  pDupCertContext;
    PCERT_PUBLIC_KEY_INFO pOldPubKey = NULL;
    PCERT_PUBLIC_KEY_INFO pNewPubKey;
    char pszStoreName[256];
    char pszNameString[256];
    char fResponse = 'n';
    char x;

    // Get the name of the certificate store to open. 
    printf("This program maintains the contents of a certificate\n");
    printf("store by allowing you to delete any excess certificates\n");
    printf("from a store. \n\n");
    printf("Please enter the name of the system store to maintain:");
    fgets(pszStoreName, 255, stdin);
    if (pszStoreName[strlen(pszStoreName) - 1] == '\n')
        pszStoreName[strlen(pszStoreName) - 1] = '\0';
    printf("Certificates will be deleted from the %s store.\n", pszStoreName);

    // Open a system certificate store.
    if (hStoreHandle = CertOpenSystemStoreA(NULL, pszStoreName)) {
        printf("The %s store has been opened. \n", pszStoreName);
    } else {
        MyHandleError("The store was not opened.");
    }

    // Find the certificates in the system store. 
    while (pCertContext = CertEnumCertificatesInStore(
        hStoreHandle,
        pCertContext)) // on the first call to the function, this parameter is NULL
                       // on all subsequent calls, it is the last pointer returned by the function
    {
        // Get and display the name of the subject of the certificate.
        if (CertGetNameStringA(pCertContext,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               pszNameString,
                               128)) {
            printf("\nCertificate for %s \n", pszNameString);
        } else {
            MyHandleError("CertGetName failed.");
        }

        // Check to determine whether the issuer and the subject are the same.
        if (CertCompareCertificateName(MY_ENCODING_TYPE,
                                       &(pCertContext->pCertInfo->Issuer),
                                       &(pCertContext->pCertInfo->Subject))) {
            printf("The certificate subject and issuer are the same.\n");
        } else {
            printf("The certificate subject and issuer are not the same.\n");
        }

        // Determine whether this certificate's public key matches 
        // the public key of the last certificate.
        pNewPubKey = &(pCertContext->pCertInfo->SubjectPublicKeyInfo);
        if (pOldPubKey)
            if (CertComparePublicKeyInfo(MY_ENCODING_TYPE, pOldPubKey, pNewPubKey)) {
                printf("The public keys are the same.\n");
            } else {
                printf("This certificate has a different public key.\n");
            }

        pOldPubKey = pNewPubKey;// Reset the old key.

        // Determine whether this certificate is to be deleted. 
        printf("Would you like to delete this certificate? (y/n) ");
        fResponse = getchar();
        if (fResponse == 'y') {
            // Create a duplicate pointer to the certificate to be deleted. 
            // In this way, the original pointer is not freed 
            // when the certificate is deleted from the store 
            // and the enumeration of the certificates in the store can continue.
            // If the original pointer is used, after the 
            // certificate is deleted, the enumeration loop stops.

            if (pDupCertContext = CertDuplicateCertificateContext(pCertContext)) {
                printf("A duplicate pointer was created. Continue. \n");
            } else {
                MyHandleError("Duplication of the certificate pointer failed.");
            }

            // Compare the pCertInfo members of the two certificates to determine whether they are identical.
            if (CertCompareCertificate(X509_ASN_ENCODING, pDupCertContext->pCertInfo, pCertContext->pCertInfo)) {
                printf("The two certificates are identical. \n");
            } else {
                printf("The two certificates are not identical. \n");
            }

            // Delete the certificate.
            if (CertDeleteCertificateFromStore(pDupCertContext)) {
                printf("The certificate has been deleted. Continue. \n");
            } else {
                printf("The deletion of the certificate failed.\n");
            }
        } // end if

        x = getchar();// Clear the input buffer.
    } // end while

    // Clean up.
    CertCloseStore(hStoreHandle, 0);
    printf("The program ran to completion successfully. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void CertificateStoreOperations(void)
/*
Example C Program: Certificate Store Operations
2018/05/31

The following example demonstrates a number of common certificate store operations as well as the following tasks and
CryptoAPI functions:

Opening and closing memory and system stores using CertOpenStore and CertCloseStore.
Duplicating an open store using CertDuplicateStore.
Finding in stores certificates that meet some criteria using CertFindCertificateInStore.
Creating a new certificate context from the encoded portion of an existing certificate using CertCreateCertificateContext.
Adding a retrieved certificate to a store in memory using CertAddCertificateContextToStore.
Adding a link to a certificate to a store using CertAddCertificateLinkToStore.
Saving the store in memory to a file on disk.
Opening and closing a file-based certificate store.
This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

This example uses the CreateMyDACL function, defined in the Creating a DACL topic,
to ensure the open file is created with a proper DACL.

This example creates a certificate store in memory.
A system store is opened and duplicated.
A certificate is retrieved from the system store.
A new certificate is created from the encoded portion of the certificate retrieved.
The certificate retrieved is added to the memory store.
A second certificate is retrieved from the My store and a link to that certificate is added to the memory store.
The certificate and the link are then retrieved from the memory store and the memory is saved to disk.
All of the stores and files are closed.
Next, the file store is reopened and a search is done for the certificate link.
The success of this program depends upon a My store being available.
That store must include a certificate with the subject "Insert_cert_subject_name1,"
and a second certificate with the subject "Insert_cert_subject_name2."
The names of the subjects must be changed to the names of certificate subjects known to be in the My store.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-certificate-store-operations
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.
    HCERTSTORE  hSystemStore;              // System store handle
    HCERTSTORE  hMemoryStore;              // Memory store handle
    HCERTSTORE  hDuplicateStore;           // Handle for a store to be created as a duplicate of an open store
    PCCERT_CONTEXT  pDesiredCert = NULL;   // Set to NULL for the first call to CertFindCertificateInStore
    PCCERT_CONTEXT  pCertContext;
    HANDLE  hStoreFileHandle = INVALID_HANDLE_VALUE;             // Output file handle 
    LPCWSTR  pszFileName = L"TestStor.sto";  // Output file name
    SECURITY_ATTRIBUTES sa;                // For DACL

    // Open a new certificate store in memory.
    if (hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,    // Memory store
        0,                         // Encoding type not used with a memory store
        NULL,                      // Use the default provider
        0,                         // No flags
        NULL))                     // Not needed
    {
        printf("Opened a memory store. \n");
    } else {
        MyHandleError("Error opening a memory store.");
    }

    // Open the My system store using CertOpenStore.
    if (hSystemStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM, // System store will be a virtual store
        0,                      // Encoding type not needed with this PROV
        NULL,                   // Accept the default HCRYPTPROV
        CERT_SYSTEM_STORE_CURRENT_USER, // Set the system store location in the registry
        L"MY"))                 // Could have used other predefined system stores
                                // including Trust, CA, or Root
    {
        printf("Opened the MY system store. \n");
    } else {
        MyHandleError("Could not open the MY system store.");
    }

    // Create a duplicate of the My store.
    if (hDuplicateStore = CertDuplicateStore(hSystemStore)) {
        printf("The MY store is duplicated.\n");
    } else {
        printf("Duplication of the MY store failed.\n.");
    }

    // Close the duplicate store. 
    if (hDuplicateStore)
        CertCloseStore(hDuplicateStore, CERT_CLOSE_STORE_CHECK_FLAG);

    // Get a certificate that has the string "Insert_cert_subject_name1" in its subject. 
    if (pDesiredCert = CertFindCertificateInStore(
        hSystemStore,
        MY_ENCODING_TYPE,             // Use X509_ASN_ENCODING
        0,                            // No dwFlags needed 
        CERT_FIND_SUBJECT_STR,        // Find a certificate with a subject that matches the 
                                      // string in the next parameter
        L"Insert_cert_subject_name1", // The Unicode string to be found in a certificate's subject
        NULL))                        // NULL for the first call to the function 
                                      // In all subsequent calls, it is the last pointer
                                      // returned by the function
    {
        printf("The desired certificate was found. \n");
    } else {
        MyHandleError("Could not find the desired certificate.");
    }

    // pDesiredCert is a pointer to a certificate with a subject that 
    // includes the string "Insert_cert_subject_name1", the string is 
    // passed as parameter #5 to the function.

    //  Create a new certificate from the encoded part of an available certificate.
    if (pCertContext = CertCreateCertificateContext(
        MY_ENCODING_TYPE,            // Encoding type
        pDesiredCert->pbCertEncoded,   // Encoded data from the certificate retrieved
        pDesiredCert->cbCertEncoded))  // Length of the encoded data
    {
        printf("A new certificate has been created.\n");
    } else {
        MyHandleError("A new certificate could not be created.");
    }

    // Add the certificate from the My store to the new memory store.
    if (CertAddCertificateContextToStore(
        hMemoryStore,                // Store handle
        pDesiredCert,                // Pointer to a certificate
        CERT_STORE_ADD_USE_EXISTING,
        NULL)) {
        printf("Certificate added to the memory store. \n");
    } else {
        MyHandleError("Could not add the certificate to the memory store.");
    }

    // Find a different certificate in the My store, and add to it a link to the memory store.

    // Find the certificate context just added to the memory store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);

    if (pDesiredCert = CertFindCertificateInStore(
        hSystemStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // no dwFlags needed 
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the 
                                     // string in the next parameter
        L"Insert_cert_subject_name2",// The Unicode string to be found in a certificate's subject
        NULL))                       // NULL for the first call to the function 
                                     // In all subsequent calls, it is the last pointer
                                     // returned by the function
    {
        printf("The second certificate was found. \n");
    } else {
        MyHandleError("Could not find the second certificate.");
    }

    // Add a link to the second certificate from the My store to the new memory store.
    if (CertAddCertificateLinkToStore(
        hMemoryStore,           // Store handle
        pDesiredCert,           // Pointer to a certificate
        CERT_STORE_ADD_USE_EXISTING,
        NULL)) {
        printf("Certificate link added to the memory store. \n");
    } else {
        MyHandleError("Could not add the certificate link to the memory store.");
    }

    // Find the first certificate in the memory store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);

    if (pDesiredCert = CertFindCertificateInStore(
        hMemoryStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed 
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        L"Insert_cert_subject_name1",// The Unicode string to be found in a certificate's subject
        NULL))                       // NULL for the first call to the function
                                     // In all subsequent calls, it is the last pointer
                                     // returned by the function
    {
        printf("The desired certificate was found in the memory store. \n");
    } else {
        printf("Certificate not in the memory store.\n");
    }

    // Find the certificate link in the memory store.

    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);

    if (pDesiredCert = CertFindCertificateInStore(
        hMemoryStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed 
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the 
                                     // string in the next parameter
        L"Insert_cert_subject_name1",// The Unicode string to be found in a certificate's subject
        NULL))                       // NULL for the first call to the function
                                     // In all subsequent calls, it is the last pointer
                                     // returned by the function
    {
        printf("The certificate link was found in the memory store. \n");
    } else {
        printf("The certificate link was not in the memory store.\n");
    }

    // Create a file in which to save the new store and certificate.

    // Create a DACL for the file.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    // Call the function to set the DACL. The DACL is set in the SECURITY_ATTRIBUTES 
    // lpSecurityDescriptor member.
    // if !CreateMyDACL(&sa), call MyHandleError("CreateMyDACL failed.");

    if (hStoreFileHandle = CreateFile(
        pszFileName,        // File path
        GENERIC_WRITE,      // Access mode
        0,                  // Share mode
        &sa,                // Security 
        CREATE_ALWAYS,      // How to create the file
        FILE_ATTRIBUTE_NORMAL, // File attributes
        NULL))              // Template
    {
        printf("Created a new file on disk. \n");
    } else {
        MyHandleError("Could not create a file on disk.");
    }

    // hStoreFileHandle is the output file handle.
    // Save the memory store and its certificate to the output file.
    if (CertSaveStore(
        hMemoryStore,        // Store handle
        0,                   // Encoding type not needed here
        CERT_STORE_SAVE_AS_STORE,
        CERT_STORE_SAVE_TO_FILE,
        hStoreFileHandle,    // This is the handle of an open disk file
        0))                  // dwFlags
                             // No flags needed here
    {
        printf("Saved the memory store to disk. \n");
    } else {
        MyHandleError("Could not save the memory store to disk.");
    }

    // Close the stores and the file. Reopen the file store, and check its contents.
    if (hMemoryStore)
        CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG);

    if (hSystemStore)
        CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);

    if (hStoreFileHandle)
        CloseHandle(hStoreFileHandle);

    printf("All of the stores and files are closed. \n");

    //  Reopen the file store.
    if (hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_FILENAME,    // Store provider type
        MY_ENCODING_TYPE,            // If needed, use the usual encoding types
        NULL,                        // Use the default HCRYPTPROV
        0,                           // Accept the default for all dwFlags
        L"TestStor.sto"))           // The name of an existing file as a Unicode string
    {
        printf("The file store has been reopened. \n");
    } else {
        printf("The file store could not be reopened. \n");
    }

    // Find the certificate link in the reopened file store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);

    if (pDesiredCert = CertFindCertificateInStore(
        hMemoryStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed 
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        L"Insert_cert_subject_name1",// The Unicode string to be found in a certificate's subject
        NULL))                       // NULL for the first call to the function
                                     // In all subsequent calls, it is the last pointer
                                     // returned by the function
    {
        printf("The certificate link was found in the file store. \n");
    } else {
        printf("The certificate link was not in the file store.\n");
    }

    // Clean up memory and end.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (hMemoryStore)
        CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG);
    if (hSystemStore)
        CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);
    if (hStoreFileHandle)
        CloseHandle(hStoreFileHandle);
    printf("All of the stores and files are closed. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Example that uses CertSerializeCertificateStoreElement to
// serialize the data from a certificate, 
// and CertAddSerializedElementToStore to add that data as a new certificate to a store.
// CertAddEncodeCertificateToStore is also demonstrated.


void SerializingCertificates(void)
/*
Example C Program: Serializing Certificates
2018/05/31

The following example demonstrates serializing a certificate context and
its properties into a form that can be stored in a file,
sent with an email message, or otherwise transmitted to another user.
The example also shows how the serialized certificate can be changed back into a certificate and
added to a certificate store.
The same process works also with CRLs and CTLs using CertSerializeCRLStoreElement and
CertSerializeCTLStoreElement.

This example illustrates the following tasks and CryptoAPI functions:

Opening a system certificate store using CertOpenSystemStore.
Opening a certificate store using CertOpenStore.
Retrieving a certificate from a store using CertEnumCertificatesInStore.
Getting the name of the certificate's subject using CertGetNameString.
Creating a serialized form of a certificate context and
its properties using CertSerializeCertificateStoreElement.
Creating a new certificate from a serialized string and
adding it into a certificate store using CertAddSerializedElementToStore.
Using CertAddEncodedCertificateToStore to create a new certificate from the encoded portion of an existing certificate.
Using CertCloseStore to close a certificate store.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-serializing-certificates
*/
{
    // Declare and initialize variables.
    HCERTSTORE         hSystemStore;
    HCERTSTORE         hFileStore;
    PCCERT_CONTEXT     pCertContext = NULL;
    char               pszNameString[256];
    BYTE * pbElement;
    DWORD              cbElement = 0;

    // Open a system certificate store.
    if (hSystemStore = CertOpenSystemStoreA(0, "CA")) {
        printf("The CA system store is open. Continue.\n");
    } else {
        MyHandleError("The first system store did not open.");
    }

    // Open a second store.
    // In order to work, a file-based certificate store named 
    // teststor.sto must be available in the working directory.
    if (hFileStore = CertOpenStore(CERT_STORE_PROV_FILENAME, MY_ENCODING_TYPE, NULL, 0, L"testStor.sto")) {
        printf("The file store is open. Continue.\n");
    } else {
        MyHandleError("The file store did not open.");
    }

    // Retrieve the first certificate from the Root store.
    // CertFindCertificateInStore could be used here to find a certificate with a specific property.
    if (pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext)) {
        printf("A certificate is available. Continue.\n");
    } else {
        MyHandleError("No certificate available. The store may be empty.");
    }

    //  Find and print the name of the subject of the certificate just retrieved.
    if (CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128)) {
        printf("Certificate for %s has been retrieved.\n", pszNameString);
    } else {
        printf("CertGetName failed. \n");
    }

    // Find out how much memory to allocate for the serialized element.
    if (CertSerializeCertificateStoreElement(
        pCertContext,      // The existing certificate.
        0,                 // Accept default for dwFlags, 
        NULL,              // NULL for the first function call.
        &cbElement))       // Address where the length of the serialized element will be placed.
    {
        printf("The length of the serialized string is %d.\n", cbElement);
    } else {
        MyHandleError("Finding the length of the serialized element failed.");
    }

    // Allocate memory for the serialized element.
    if (pbElement = (BYTE *)malloc(cbElement)) {
        printf("Memory has been allocated. Continue.\n");
    } else {
        MyHandleError("The allocation of memory failed.");
    }

    // Create the serialized element from a certificate context.
    if (CertSerializeCertificateStoreElement(
        pCertContext,        // The certificate context source for the serialized element.
        0,                   // dwFlags. Accept the default.
        pbElement,           // A pointer to where the new element will be stored.
        &cbElement))         // The length of the serialized element,
    {
        printf("The encoded element has been serialized. \n");
    } else {
        MyHandleError("The element could not be serialized.");
    }

    //  pbElement could be written to a file or be sent by email to another user. 
    //  The following process uses the serialized 
    //  pbElement and its length, cbElement, to add a new certificate to a store.
    if (CertAddSerializedElementToStore(
        hFileStore,          // Store where certificate is to be added.
        pbElement,           // The serialized element for another certificate. 
        cbElement,           // The length of pbElement.  
        CERT_STORE_ADD_REPLACE_EXISTING,
        // Flag to indicate what to do if a matching
        // certificate is already in the store.
        0,                   // dwFlags. Accept the default.
        CERT_STORE_CERTIFICATE_CONTEXT_FLAG,
        NULL,
        NULL
    )) {
        printf("The new certificate is added to the second store.\n");
    } else {
        MyHandleError("The new element was not added to a store.");
    }

    //  Next, another certificate will be retrieved from the system store
    //  and its encoded part, pCertContext->pbCertEncoded, will be
    //  used to create a new certificate to be added to the file store.
    if (pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext)) {
        printf("Another certificate is available. Continue.\n");
    } else {
        MyHandleError("No certificate is available. The store may be empty.");
    }

    //  Find and print the name of the subject of the certificate just retrieved.
    if (CertGetNameStringA(pCertContext,
                           CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           0,
                           NULL,
                           pszNameString,
                           128)) {
        printf("Certificate for %s has been retrieved.\n", pszNameString);
    } else {
        printf("CertGetName failed. \n");
    }

    //  Create a new certificate from the encoded portion of pCertContext and add it to the file-based store.
    if (CertAddEncodedCertificateToStore(hFileStore,
                                         MY_ENCODING_TYPE,
                                         pCertContext->pbCertEncoded,
                                         pCertContext->cbCertEncoded,
                                         CERT_STORE_ADD_USE_EXISTING,
                                         NULL)) {
        printf("Another certificate is added to the file store.\n");
    } else {
        MyHandleError("The new certificate was not added to the file store.");
    }

    // Free memory.
    free(pbElement);
    CertCloseStore(hSystemStore, 0);
    CertCloseStore(hFileStore, 0);
    printf("The program ran without error to the end.\n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//   Copyright (C) Microsoft.  All rights reserved.
//   Declare functions MyHandleError and My_Wait.
//   These functions are defined at the end of the file.


void My_Wait()
{
    printf("Hit enter to continue.");
    (void)getchar();
}


void GettingAndSettingCertificateProperties(void)
/*
Example C Program: Getting and Setting Certificate Properties
2018/05/31

The following example gets and sets certificate properties,
and illustrates the following tasks and CryptoAPI functions.

Opening a system store by using CertOpenSystemStore.
Using CertEnumCertificatesInStore to list all of the certificates in the open store.
Retrieving and printing the subject name from the certificate by using CertGetNameString.
Setting the enhanced key usage property on certificates by using the CertAddEnhancedKeyUsageIdentifier function.
Setting the display name property on the certificate by using CertSetCertificateContextProperty.
Retrieving a certificate's properties by using CertGetCertificateContextProperty.
Closing a certificate store by using CertCloseStore with the CERT_CLOSE_STORE_CHECK_FLAG flag.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-getting-and-setting-certificate-properties
*/
{
    // This program shows all of the certificates in a 
    // certificate store and lists all of the property ID numbers of all of the certificate contexts.

    // It also adds an enhanced key usage identifier to every other certificate.

    //  Declare and initialize local variables.
    HANDLE           hCertStore;
    PCCERT_CONTEXT   pCertContext = NULL;
    CRYPT_KEY_PROV_INFO * pCryptKeyProvInfo;
    char pszNameString[256];
    char pszStoreName[256] = {0};
    char fResponse;
    char fExtra;
    BYTE * pName = (BYTE *)"Temp Name.";
    CRYPT_DATA_BLOB  Friendly_Name_Blob = {32,pName};
    void * pvData;
    DWORD            cbData = 0;
    DWORD            dwFlags = CERT_STORE_NO_CRYPT_RELEASE_FLAG;
    DWORD            dwPropId = 0;   // 0 must be used on the first call to the function. After that,
                                     // the last returned property ID is passed.
    LPCSTR  pszUsageIdentifier = szOID_RSA_RC4;
    int count = 0;

    fprintf(stderr, "Please enter the store name :");
    scanf_s("%s", pszStoreName);
    fprintf(stderr, "The store name is %s .\n", pszStoreName);
    My_Wait();

    // Open the named system certificate store. 
    if (!(hCertStore = CertOpenSystemStoreA(NULL, pszStoreName))) {
        MyHandleError("Store not opened.");
    }

    // The file is open. Continue.
    // In a loop, use CertEnumCertificatesInStore to get the each certificate in the store. 
    while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
        //  First, retrieve and print the subject name from the certificate.
        if (CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128)) {
            printf("\nNew Cert for %s \n", pszNameString);
        } else {
            printf("The get name failed.\n");
        }

        //  Set the enhanced key usage property on every other certificate.
        if (count == 0) {
            count++;
            if (CertAddEnhancedKeyUsageIdentifier(pCertContext, pszUsageIdentifier)) {
                printf("Enhanced key usage set.\n");
            } else {
                printf("Enhanced key usage was not set.\n");
            }
        } else
            //   Do not set the usage, but reset the counter so that the property
            //   will be set on the next certificate.
            //   Ask if the user would like to set a display name.
        {
            printf("Would you like to set the display name ?");
            scanf_s("%c%c", &fResponse, &fExtra);
            if (fResponse == 'y') {
                if (CertSetCertificateContextProperty(pCertContext,
                                                      CERT_FRIENDLY_NAME_PROP_ID,
                                                      0,
                                                      &Friendly_Name_Blob)) {
                    printf("A name has been set.\n");
                } else {
                    printf("The display name was not set.\n");
                }
            }
            count = 0;
        }

        // In a loop, find all of the property IDs for the given certificate.
        // The loop continues until the CertEnumCertificateContextProperties returns 0.
        while (dwPropId = CertEnumCertificateContextProperties(
            pCertContext, // the context whose properties are to be listed.
            dwPropId))    // number of the last property found. Must be 0 to find the first property ID.
        {
            // Each time through the loop, a property ID has been found.
            // Print the property number and information about the property.

            printf("Property # %d found->", dwPropId);
            switch (dwPropId) {
            case CERT_FRIENDLY_NAME_PROP_ID:
            {
                //  Retrieve the actual display name certificate property.
                //  First, get the length of the property setting the
                //  pvData parameter to NULL to get a value for cbData
                //  to be used to allocate memory for the pvData buffer.
                printf("FRIENDLY_NAME_PROP_ID ");
                if (!(CertGetCertificateContextProperty(pCertContext, dwPropId, NULL, &cbData))) {
                    MyHandleError("Call #1 to property length failed.");
                }
                // The call succeeded. Use the size to allocate memory for the property.
                if (!(pvData = (void *)malloc(cbData))) {
                    MyHandleError("Memory allocation failed.");
                }
                // Allocation succeeded. Retrieve the property data.
                if (!(CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, &cbData))) {
                    MyHandleError("Call #2 getting the data failed.");
                } else {
                    printf("\n  The display name is -> %s.", pvData);
                    free(pvData);
                }
                break;
            }
            case CERT_SIGNATURE_HASH_PROP_ID:
            {
                printf("Signature hash ID. ");
                break;
            }
            case CERT_KEY_PROV_HANDLE_PROP_ID:
            {
                printf("KEY PROVE HANDLE.");
                break;
            }
            case CERT_KEY_PROV_INFO_PROP_ID:
            {
                printf("KEY PROV INFO PROP ID.");
                if (!(CertGetCertificateContextProperty(
                    pCertContext,  // A pointer to the certificate where the property will be set.
                    dwPropId,      // An identifier of the property to get. 
                                   // In this case, CERT_KEY_PROV_INFO_PROP_ID
                    NULL,          // NULL on the first call to get the length.
                    &cbData)))     // The number of bytes that must be allocated for the structure.
                {
                    MyHandleError("The property length was not retrieved.");
                }
                if (!(pCryptKeyProvInfo = (CRYPT_KEY_PROV_INFO *)malloc(cbData))) {
                    MyHandleError("Error in allocation of memory.");
                }
                if (CertGetCertificateContextProperty(pCertContext, dwPropId, pCryptKeyProvInfo, &cbData)) {
                    printf("\n The current key container is %S.", pCryptKeyProvInfo->pwszContainerName);
                    free(pCryptKeyProvInfo);
                } else {
                    free(pCryptKeyProvInfo);
                    MyHandleError("The property was not retrieved.");
                }
                break;
            }
            case CERT_SHA1_HASH_PROP_ID:
            {
                printf("SHA1 HASH id.");
                break;
            }
            case CERT_MD5_HASH_PROP_ID:
            {
                printf("md5 hash id. ");
                break;
            }
            case CERT_KEY_CONTEXT_PROP_ID:
            {
                printf("KEY CONTEXT PROP id.");
                break;
            }
            case CERT_KEY_SPEC_PROP_ID:
            {
                printf("KEY SPEC PROP id.");
                break;
            }
            case CERT_ENHKEY_USAGE_PROP_ID:
            {
                printf("ENHKEY USAGE PROP id.");
                break;
            }
            case CERT_NEXT_UPDATE_LOCATION_PROP_ID:
            {
                printf("NEXT UPDATE LOCATION PROP id.");
                break;
            }
            case CERT_PVK_FILE_PROP_ID:
            {
                printf("PVK FILE PROP id. ");
                break;
            }
            case CERT_DESCRIPTION_PROP_ID:
            {
                printf("DESCRIPTION PROP id. ");
                break;
            }
            case CERT_ACCESS_STATE_PROP_ID:
            {
                printf("ACCESS STATE PROP id. ");
                break;
            }
            case CERT_SMART_CARD_DATA_PROP_ID:
            {
                printf("SMAART_CARD DATA PROP id. ");
                break;
            }
            case CERT_EFS_PROP_ID:
            {
                printf("EFS PROP id. ");
                break;
            }
            case CERT_FORTEZZA_DATA_PROP_ID:
            {
                printf("FORTEZZA DATA PROP id.");
                break;
            }
            case CERT_ARCHIVED_PROP_ID:
            {
                printf("ARCHIVED PROP id.");
                break;
            }
            case CERT_KEY_IDENTIFIER_PROP_ID:
            {
                printf("KEY IDENTIFIER PROP id. ");
                break;
            }
            case CERT_AUTO_ENROLL_PROP_ID:
            {
                printf("AUTO ENROLL id. ");
                break;
            }
            }  // end switch
            printf("\n");
        } // end the inner while loop. This is the end of the display of
          // a single property of a single certificate.

        My_Wait();
    } // end the outer while loop. Move on to the next certificate.

    // Free Memory and close the open store.
    if (pCertContext) {
        CertFreeCertificateContext(pCertContext);
    }
    CertCloseStore(hCertStore, 0);
    printf("The function completed successfully.\n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Example C Program: 
// Converting a name from a certificate to an ASN.1 encoded string and back.


// Declare auxiliary functions
void Local_wait()
{
    //  This function prints a prompt string 
    //  and wait for the user to hit enter.
    //  It provides a pause with its length controlled by the user.

    _tprintf(TEXT("Hit Enter to continue : "));
    (void)getchar();
}


void ConvertingNamesfromCertificatesToASNAndBack(void)
/*
Example C Program: Converting Names from Certificates to ASN.1 and Back
2018/05/31

The following example enumerates the certificates in a certificate store,
displays the subject and user of each certificate,
and converts the subject name from each certificate into its Abstract Syntax Notation One (ASN.1) encoded form,
and then back in to its decoded form.

This example shows the following tasks and CryptoAPI functions:

Opening a system store using CertOpenSystemStore.
Using CertEnumCertificatesInStore to get the first certificate from the open store.
Using CertGetNameString to get the subject name and the user name from the certificate.
Using CertNameToStr to convert the subject name from the certificate into its ASN.1 encoded form.
Using CertStrToName to convert an ASN.1 encoded string into its decoded form.
Closing a certificate store using CertCloseStore with the CERT_CLOSE_STORE_CHECK_FLAG flag.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-converting-names-from-certificates-to-asn1-and-back
*/
{
    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pCertContext;

    // Begin Processing by opening a certificate store.
    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     MY_ENCODING_TYPE,
                                     NULL,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"MY"))) {
        MyHandleError(TEXT("The MY system store did not open."));
    }

    //       Loop through the certificates in the store. 
    //       For each certificate,
    //             get and print the name of the certificate subject and issuer.
    //             convert the subject name from the certificate
    //                  to an ASN.1 encoded string and print the octets from that string.
    //             convert the encoded string back into its form in the certificate.
    pCertContext = NULL;
    while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
        LPTSTR pszString;
        LPTSTR pszName;
        DWORD cbSize;
        CERT_BLOB blobEncodedName;

        //        Get and display the name of subject of the certificate.
        if (!(cbSize = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0))) {
            MyHandleError(TEXT("CertGetName 1 failed."));
        }

        if (!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR)))) {
            MyHandleError(TEXT("Memory allocation failed."));
        }

        if (CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszName, cbSize)) {
            _tprintf(TEXT("\nSubject -> %s.\n"), pszName);
            free(pszName);//       Free the memory allocated for the string.
        } else {
            MyHandleError(TEXT("CertGetName failed."));
        }

        //        Get and display the name of Issuer of the certificate.
        if (!(cbSize = CertGetNameString(pCertContext,
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         CERT_NAME_ISSUER_FLAG,
                                         NULL,
                                         NULL,
                                         0))) {
            MyHandleError(TEXT("CertGetName 1 failed."));
        }

        if (!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR)))) {
            MyHandleError(TEXT("Memory allocation failed."));
        }

        if (CertGetNameString(pCertContext,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              CERT_NAME_ISSUER_FLAG,
                              NULL,
                              pszName,
                              cbSize)) {
            _tprintf(TEXT("Issuer  -> %s.\n"), pszName);
            free(pszName);//       Free the memory allocated for the string.
        } else {
            MyHandleError(TEXT("CertGetName failed."));
        }

        //       Convert the subject name to an ASN.1 encoded string and print the octets in that string.

        //       First : Get the number of bytes that must be allocated for the string.
        cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
                               &(pCertContext->pCertInfo->Subject),
                               MY_STRING_TYPE,
                               NULL,
                               0);
        //  The function CertNameToStr returns the number of bytes needed for a string to hold the
        //  converted name, including the null terminator.         
        if (1 == cbSize) {//  If it returns one, the name is an empty string.
            MyHandleError(TEXT("Subject name is an empty string."));
        }

        //        Allocated the needed buffer. Note that this
        //        memory must be freed inside the loop or the application will leak memory.
        if (!(pszString = (LPTSTR)malloc(cbSize * sizeof(TCHAR)))) {
            MyHandleError(TEXT("Memory allocation failed."));
        }

        //       Call the function again to get the string. 
        cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
                               &(pCertContext->pCertInfo->Subject),
                               MY_STRING_TYPE,
                               pszString,
                               cbSize);
        //  The function CertNameToStr returns the number of bytes in the string, including the null terminator.        
        if (1 == cbSize) {//  If it returns 1, the name is an empty string.
            MyHandleError(TEXT("Subject name is an empty string."));
        }

        //    Get the length needed to convert the string back 
        //    back into the name as it was in the certificate.
        if (!(CertStrToName(
            MY_ENCODING_TYPE,
            pszString,
            MY_STRING_TYPE,
            NULL,
            NULL,        // NULL to get the number of bytes needed for the buffer.          
            &cbSize,     // Pointer to a DWORD to hold the number of bytes needed for the buffer
            NULL)))      // Optional address of a pointer to old the location for an error in the input string.
        {
            MyHandleError(TEXT("Could not get the length of the BLOB."));
        }

        if (!(blobEncodedName.pbData = (LPBYTE)malloc(cbSize))) {
            MyHandleError(TEXT("Memory Allocation for the BLOB failed."));
        }
        blobEncodedName.cbData = cbSize;

        if (CertStrToName(MY_ENCODING_TYPE,
                          pszString,
                          MY_STRING_TYPE,
                          NULL,
                          blobEncodedName.pbData,
                          &blobEncodedName.cbData,
                          NULL)) {
            _tprintf(TEXT("CertStrToName created the BLOB.\n"));
        } else {
            MyHandleError(TEXT("Could not create the BLOB."));
        }

        //       Free the memory.
        free(blobEncodedName.pbData);
        free(pszString);

        Local_wait();//       Pause before information on the next certificate is displayed.
    } // End of while loop

    _tprintf(TEXT("\nThere are no more certificates in the store. \n"));

    //   Close the MY store.
    if (CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG)) {
        _tprintf(TEXT("The store is closed. ")
                 TEXT("All certificates are released.\n"));
    } else {
        _tprintf(TEXT("The store was closed, ")
                 TEXT("but certificates still in use.\n"));
    }

    _tprintf(TEXT("This demonstration program ran to completion ")
             TEXT("without error.\n"));

    Local_wait();
}


//////////////////////////////////////////////////////////////////////////////////////////////////
/*
Working with Certificate Stores
2018/05/31

The following topics present code fragments and example C programs for certificate store operations.

Example C Code for Opening Certificate Stores
Example C Program: Collection and Sibling Certificate Store Operations
Example C Program: Registering Physical and System Certificate Stores
Example C Program: Setting and Getting Certificate Store Properties
Example C Program: Listing System and Physical Stores
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


void CollectionAndSiblingCertificateStoreOperations(void)
/*
Example C Program: Collection and Sibling Certificate Store Operations
05/31/2018

The following example demonstrates the concept of the collection store,
a temporary certificate store that actually includes the contents of several certificate stores.
One or more stores may be added to a collection that can access the contents of any of the stores in the collection with a single function call.

This example illustrates the following tasks and CryptoAPI functions:

Opening and closing a collection store, a memory store and a system store using CertOpenStore and CertCloseStore.
Adding a sibling store to a collection store using CertAddStoreToCollection.
Finding certificates and links to certificates in stores that meets some criteria using CertFindCertificateInStore.
Adding a retrieved certificate to a store in memory using CertAddCertificateContextToStore.
Adding a link to a certificate to a store using CertAddCertificateLinkToStore.
Saving the store in memory to a file on disk.
Opening and closing a file-based certificate store.
Removing a sibling store from a collection using CertRemoveStoreFromCollection.
This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

This example uses the CreateMyDACL function, defined in the Creating a DACL topic,
to ensure the open file is created with a proper DACL.

The following example opens a collection store, creates a new certificate store in memory,
and adds the new store as a sibling store to the collection store.
The program then opens a system store and retrieves a certificate.
That certificate is added to the memory store.
A second certificate is retrieved from the system store and a link to that certificate is added to the memory store.
The certificate and the link are then retrieved from the collection store showing that certificates and
links in a sibling store can be retrieved from the collection store.
The memory is saved to disk. The memory store is then removed from the collection.
The link added to the memory store can still be found in the memory store but can no longer be found in the collection store.
All of the stores and files are closed, then the file store is reopened and a search is done for the certificate link.
The success of this program depends upon a My store being available.
That store must include a certificate with the subject "Insert_cert_subject_name1" and
a second certificate with the subject "Insert_cert_subject_name2".
The names of the subjects should be changed to the names of certificate subjects known to be in the My store.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-collection-and-sibling-certificate-store-operations
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.

    HCERTSTORE  hCollectionStore;           // Collection store handle
    HCERTSTORE  hSystemStore;               // System store handle
    HCERTSTORE  hMemoryStore;               // Memory store handle
    PCCERT_CONTEXT  pDesiredCert = NULL;    // Set to NULL for the first call to CertFindCertificateInStore
    HANDLE hStoreFileHandle;               // Output file handle
    LPCWSTR pszFileName = L"TestStor.sto";    // Output file name
    SECURITY_ATTRIBUTES sa;                 // for DACL
    LPCWSTR pswzFirstCert = L"Insert_cert_subject_name1";
    // Subject of the first certificate
    LPCWSTR pswzSecondCert = L"Insert_cert_subject_name2";
    // Subject of the second certificate

// Open a collection certificate store.
    if (hCollectionStore = CertOpenStore(
        CERT_STORE_PROV_COLLECTION, // Collection store
        0,                          // Encoding type 
                                    // Not used with a collection store
        NULL,                       // Use the default provider
        0,                          // No flags
        NULL))                      // Not needed
    {
        printf("Opened a collection store. \n");
    } else {
        MyHandleError("Error opening the collection store.");
    }

    // Open a new certificate store in memory.
    if (hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,    // Memory store
        0,                         // Encoding type
                                   // not used with a memory store
        NULL,                      // Use the default provider
        0,                         // No flags
        NULL))                     // Not needed
    {
        printf("Opened a memory store. \n");
    } else {
        MyHandleError("Error opening a memory store.");
    }

    // Open the My system store using CertOpenStore.
    if (hSystemStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM, // System store will be a virtual store
        0,                      // Encoding type not needed  with this PROV
        NULL,                   // Accept the default HCRYPTPROV
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY"))                 // System store name
    {
        printf("Opened the My system store. \n");
    } else {
        MyHandleError("Could not open the My system store.");
    }

    // Get a certificate that has the string
    // "Insert_cert_subject_name1" in its subject. 
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hSystemStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        pswzFirstCert,               // The Unicode string to be found in a certificate's subject
        NULL))                       // NULL is used so that the search will begin at the 
                                     // beginning of the certificate store
    {
        printf("The %S certificate was found. \n", pswzFirstCert);
    } else {
        MyHandleError("Could not find the desired certificate.");
    }

    // pDesiredCert is a pointer to a certificate with a subject that 
    // includes the string passed as parameter five to the function.

    // Add the certificate from the My store to the memory store.
    if (CertAddCertificateContextToStore(
        hMemoryStore,                // Store handle
        pDesiredCert,                // Pointer to a certificate
        CERT_STORE_ADD_USE_EXISTING,
        NULL)) {
        printf("Certificate added to the memory store. \n");
    } else {
        MyHandleError("Could not add the certificate to the memory store.");
    }

    //  Add the memory store as a sibling to the collection store. 
    //  All certificates in the memory store will now be available in the collection store.
    //  Any new certificates added to the memory store will also be available in the collection store.
    if (CertAddStoreToCollection(
        hCollectionStore,
        hMemoryStore,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,// New certificates can be added to the sibling store
        1))                                 // The sibling store's priority
                                            // because this store has the highest priority, 
                                            // certificates added to the collection store will
                                            // actually be stored in this store
    {
        printf("The memory store is added to the collection store.\n");
    } else {
        MyHandleError("The memory store was not added to the collection.");
    }

    //  Find a different certificate in the My store, and add, to the memory store, a link to that certificate.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hSystemStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        pswzSecondCert,              // The Unicode string to be found in a certificate's subject
        NULL))                       // NULL is used so that the search will begin at the 
                                     // beginning of the certificate store
    {
        printf("The %S certificate was found. \n", pswzSecondCert);
    } else {
        MyHandleError("Could not find the second certificate.");
    }

    // Add a link to a second certificate from the My store to the new memory store.
    if (CertAddCertificateLinkToStore(
        hMemoryStore,                // store handle
        pDesiredCert,                // pointer to a certificate
        CERT_STORE_ADD_USE_EXISTING,
        NULL)) {
        printf("%S link added to the memory store. \n", pswzSecondCert);
    } else {
        MyHandleError("Could not add the certificate link to the memory store.");
    }

    // Find the first certificate in the memory store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hMemoryStore,                // Store handle
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        pswzFirstCert,               // The Unicode string to be found in a certificate's subject
        NULL))                       // NULL is used so that the search will begin at the 
                                     // beginning of the certificate store
    {
        printf("The %S certificate was found in the memory store. \n", pswzFirstCert);
    } else {
        printf("The %S certificate was not in the memory store.\n", pswzFirstCert);
    }

    //  Find that same certificate in the collection store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hCollectionStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        pswzFirstCert,               // The Unicode string to be found in a certificate's subject
        NULL))                       // NULL is used so that the search will begin at the 
                                     // beginning of the certificate store
    {
        printf("The %S certificate was found in the collection store. \n", pswzFirstCert);
    } else {
        printf("The %S certificate was not in the memory collection.\n", pswzFirstCert);
    }

    //  Find the certificate link in the memory store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hCollectionStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // Mo dwFlags needed
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        pswzSecondCert,              // The Unicode string to be found in a certificate's subject
        NULL))                       // NULL is used so that the search will begin at the 
                                     // beginning of the certificate store
    {
        printf("The %S link was found in the collection store. \n", pswzSecondCert);
    } else {
        printf("The %S certificate link was not in the memory store.\n", pswzSecondCert);
    }

    // Create a file to save the new store and certificate into.

    // Create a DACL for the file.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    // Call function to set the DACL. The DACL
    // is set in the SECURITY_ATTRIBUTES 
    // lpSecurityDescriptor member.
    // if CreateMyDACL(&sa) fails, call MyHandleError("CreateMyDACL failed.")

    if (hStoreFileHandle = CreateFile(pszFileName,             // File path
                                      GENERIC_WRITE,           // Access mode
                                      0,                       // Share mode
                                      &sa,                     // Security 
                                      CREATE_ALWAYS,           // How to create the file
                                      FILE_ATTRIBUTE_NORMAL,   // File attributes
                                      NULL))                   // File template
    {
        printf("Created a new file on disk. \n");
    } else {
        MyHandleError("Could not create a file on disk.");
    }

    // hStoreFileHandle is the output file handle.
    // Save the memory store and its certificate to the output file.
    if (CertSaveStore(
        hMemoryStore,            // Store handle
        0,                       // Encoding type not needed here
        CERT_STORE_SAVE_AS_STORE,
        CERT_STORE_SAVE_TO_FILE,
        hStoreFileHandle,        // The handle of an open disk file
        0))                      // dwFlags--no flags are needed here
    {
        printf("Saved the memory store to disk. \n");
    } else {
        MyHandleError("Could not save the memory store to disk.");
    }

    //  Remove the sibling store from the collection.
    //  CertRemoveStoreFromCollection returns void.
    printf("\nRemoving the memory store from the collection.\n");
    CertRemoveStoreFromCollection(hCollectionStore, hMemoryStore);

    //   Find the link in the memory store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hMemoryStore,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
        0,                           // No dwFlags needed
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter
        pswzSecondCert,              // Unicode string to be found in a certificate's subject
        NULL))                       // NULL is used so that the search will begin at the 
                                     // beginning of the certificate store
    {
        printf("The %S link is still in the memory store. \n", pswzSecondCert);
    } else {
        printf("The certificate link was not in the memory store.\n");
    }

    //  Try to find certificate link in the collection store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hCollectionStore,
        MY_ENCODING_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        pswzSecondCert,
        NULL)) {
        printf("The %S link was found in the collection store. \n", pswzSecondCert);
    } else {
        printf("Removing the store from the collection worked.\n");
        printf("The %S link is not in the collection store.\n", pswzSecondCert);
    }

    // Close the stores and the file. Reopen the file store, and check its contents.
    if (hMemoryStore)
        CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG);

    if (hSystemStore)
        CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);

    if (hStoreFileHandle)
        CloseHandle(hStoreFileHandle);

    printf("All of the stores and files are closed. \n");

    //  Reopen the file store.
    if (hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_FILENAME,    // Store provider type
        MY_ENCODING_TYPE,            // If needed, use the usual encoding types
        NULL,                        // Use the default HCRYPTPROV
        0,                           // Accept the default for all dwFlags
        L"TestStor.sto"))           // The name of an existing file as a Unicode string
    {
        printf("The file store has been reopened. \n");
    } else {
        printf("The file store could not be reopened. \n");
    }

    //  Find the certificate link in the reopened file store.
    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);
    if (pDesiredCert = CertFindCertificateInStore(
        hMemoryStore,
        MY_ENCODING_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        pswzSecondCert,
        NULL)) {
        printf("The %S certificate link was found in the file store. \n", pswzSecondCert);
    } else {
        printf("The certificate link was not in the file store.\n");
    }

    // Clean up memory and end.

    if (pDesiredCert)
        CertFreeCertificateContext(pDesiredCert);

    if (hMemoryStore)
        CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG);

    printf("All of the stores and files are closed. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void RegisteringPhysicalAndSystemCertificateStores()
/*
Example C Program: Registering Physical and System Certificate Stores
05/31/2018

Physical stores may be made more or less permanent members of a system store.
When a physical store is a member of a system store,
operations on the system store such as finding a certificate will look in all of the physical stores that are registered as members of the system store.
A physical store can be removed from membership in a system store by using an unregister function.

This example shows the following tasks and CryptoAPI functions:

Registering (creating) a new system store using CertRegisterSystemStore.
Opening a newly created system store using CertOpenStore.
Registering a physical store as a member of a system store using CertRegisterPhysicalStore.
Unregistering (deleting) a system store using CertUnregisterSystemStore.
This example also demonstrates the creation and deletion of system stores.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-registering-physical-and-system-certificate-stores
*/
{
    // Declare and initialize variables.
    HCERTSTORE hSystemStore;
    DWORD dwFlags = CERT_SYSTEM_STORE_CURRENT_USER;
    LPCWSTR pvSystemName = L"NEWSTORE";  // For this setting of dwFlags, the store name may 
                                        // be prefixed with a user name.
    CERT_PHYSICAL_STORE_INFO PhysicalStoreInfo;
    BYTE fResponse = 'n';

    if (CertRegisterSystemStore(pvSystemName, dwFlags, NULL, NULL))
        printf("System store %S is registered. \n", pvSystemName);
    else
        printf("The system store did not register. \n");

    // Open the NEWSTORE as a system store.
    if (hSystemStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,   // the store provider type
        0,                        // the encoding type is not needed
        NULL,                     // use the default HCRYPTPROV
        CERT_SYSTEM_STORE_CURRENT_USER, // set the store location in a registry location
        pvSystemName))           // the store name as a Unicode string
    {
        printf("The new store has been opened as a system store.\n");
    } else {
        printf("The new store was not opened as a system store.\n");
    }
    if (hSystemStore) {
        if (CertCloseStore(hSystemStore, 0)) {
            printf("The system store has been closed.\n");
        } else {
            printf("The system store could not be closed.\n");
        }
    } else {
        printf("The system store did not need to be closed.\n");
    }

    // Initialize PhysicalStoreInfo.
    PhysicalStoreInfo.cbSize = sizeof(CERT_PHYSICAL_STORE_INFO);
    PhysicalStoreInfo.pszOpenStoreProvider = (LPSTR)CERT_STORE_PROV_FILENAME;
    PhysicalStoreInfo.dwFlags = CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG;

    // Replace the path below with one that is appropriate for you.
    PhysicalStoreInfo.OpenParameters.pbData = (BYTE *)L"C:\\temp\\mystore";
    PhysicalStoreInfo.OpenParameters.cbData =
        (DWORD)(wcslen((LPWSTR)PhysicalStoreInfo.OpenParameters.pbData) + 1) * sizeof(WCHAR);
    PhysicalStoreInfo.dwPriority = 1;
    PhysicalStoreInfo.dwOpenEncodingType = MY_ENCODING_TYPE;

    // Register the physical store.
    if (CertRegisterPhysicalStore(L"NEWSTORE", dwFlags, L"TESTOR.STO", &PhysicalStoreInfo, NULL)) {
        printf("Physical store is registered. \n");
    } else {
        printf("The physical store was not registered.\n");
    }

    //  Next, unregister the store.
    printf("Would you like to unregister the %S store? (y/n) ", pvSystemName);
    scanf_s("%c", &fResponse);

    if (fResponse == 'y') {
        if (CertUnregisterSystemStore(pvSystemName, dwFlags)) {
            printf("System store %S has been unregistered.\n", pvSystemName);
        } else {
            printf("The system store was not unregistered.\n");
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Example C program.
// This program demonstrates the use of the following functions:
//     CreateEvent
//     CertOpenStore
//     CertSetStoreProperty
//     CertGetStoreProperty
//     CryptFindLocalizedName 
//     CertSaveStore
//     CryptGetMessageSignerCount
//     CryptGetMessageCertificates
//     CryptHashMessage
//     CertControlStore
//     WaitForSingleObjectEx
//     CertCloseStore


void SettingAndGettingCertificateStoreProperties()
/*
Example C Program: Setting and Getting Certificate Store Properties
05/31/2018

The following example sets and gets a certificate store property, the localized store name.
This property is not persisted when the store is closed.

This example illustrates the following tasks and CryptoAPI functions:

Opening a certificate store using CertOpenStore.
Setting the localized name of the store using CertSetStoreProperty.
Retrieving the localized name of the store using CertGetStoreProperty.
Retrieving the predefined localized store name using CryptFindLocalizedName.
Save the certificate store as a PKCS #7 message to a file using CertSaveStore.
Save the certificate store to a memory BLOB using CertSaveStore.
Determine the number of signers of the PKCS #7 message using CryptGetMessageSignercount.
Open a certificate store from a PKCS #7 message in memory using CryptGetMessageCertificates.
Initialize the CRYPT_ALGORITHM_IDENTIFIER and
CRYPT_HASH_MESSAGE_PARA data structures needed to hash the message
Hash and encode the message using CryptHashMessage.
Determine whether changes have been made to an open certificate store and
synchronizing the store if needed using CertControlStore.
Closing a certificate store using CertCloseStore with the CERT_CLOSE_STORE_FORCE_FLAG.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-setting-and-getting-certificate-store-properties
*/
{
    // Declare and initialize variables.
    HCERTSTORE hCertStore;     // Original certificate store
    HCERTSTORE hNewStore;      // Store to be created from a PKCS #7 message  
    HANDLE     hEvent;
    void * pvData;
    DWORD cbData = 0;
    DWORD dwSignerCount;
    CRYPT_DATA_BLOB Property_Name_Blob;   // BLOB to hold store property
    CRYPT_DATA_BLOB Save_Store_Blob;      // BLOB to hold the PKCS #7 message
    CRYPT_HASH_MESSAGE_PARA      HashPara;  // Data structure used to hash a message
    const BYTE * rgpbToBeHashed[1];
    DWORD                        rgcbToBeHashed[1];
    BYTE * pbHashedBlob;// Arrays of messages to be hashed
    DWORD                        cbHashedBlob = 0;// Length of the hash BLOB    
    CRYPT_ALGORITHM_IDENTIFIER   AlgId;     // Data structure to hold the hash algorithm identifier
    BOOL                        fSignal;

    // Initialize an event.
    if (hEvent = CreateEvent(NULL,
                             FALSE,          // Manual reset is FALSE.
                             FALSE,          // The initial state of the event is FALSE.
                             NULL)) {
        printf("An event has been created.\n");
    } else {
        MyHandleError("The event was not created.");
    }

    // Open the MY certificate store. 
    if (hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                   0,
                                   NULL,
                                   CERT_SYSTEM_STORE_CURRENT_USER,
                                   L"MY")) {
        printf("The MY store is open.\n");
    } else {
        MyHandleError("The MY store did not open.");
    }

    // Prepare a data structure to set a store property.
    // Initialize the members of the CRYPT_DATA_BLOB.
    Property_Name_Blob.pbData = (BYTE *)L"The Local MY Store";
    Property_Name_Blob.cbData = (DWORD)(wcslen((LPWSTR)Property_Name_Blob.pbData) + 1) * sizeof(WCHAR);

    // Set the store's localized name property.
    if (CertSetStoreProperty(hCertStore, CERT_STORE_LOCALIZED_NAME_PROP_ID, 0, &Property_Name_Blob)) {
        printf("The name of the store has been set. Continue. \n");
    } else {
        MyHandleError("Setting the store's localized name failed.");
    }

    // Call CertGetStoreProperty a first time to get the length of the store name string to be returned.
    if (CertGetStoreProperty(
        hCertStore,
        CERT_STORE_LOCALIZED_NAME_PROP_ID,
        NULL,     // NULL on the first call to establish the length of the string to to be returned
        &cbData)) {
        printf("The length of the property is %d. \n", cbData);
    } else {
        MyHandleError("The length of the property was not calculated.");
    }

    // cbData is the length of a string to be allocated. 
    // Allocate the space for the string, and call the function a the second time.
    if (pvData = malloc(cbData)) {
        printf("%d bytes of memory allocated.\n", cbData);
    } else {
        MyHandleError("Memory was not allocated.");
    }
    if (CertGetStoreProperty(hCertStore, CERT_STORE_LOCALIZED_NAME_PROP_ID, pvData, &cbData)) {
        printf("The localized name is %S.\n", pvData);
    } else {
        MyHandleError("CertGetStoreProperty failed.");
    }

    //   Find and print the predefined localized name for the MY store.
    //   Note that changing the localized store name property does not 
    //   change the predefined localized store name.
    printf("The predefined localized name of the MY store is still %S.\n", CryptFindLocalizedName(L"my"));

    // Save the store to a PKCS #7 message in a file.
    if (CertSaveStore(hCertStore,
                      MY_ENCODING_TYPE,
                      CERT_STORE_SAVE_AS_PKCS7,
                      CERT_STORE_SAVE_TO_FILENAME_A,
                      (void *)"pkcsseven.dat",
                      0)) {
        printf("The store has been saved to a PKCS #7 message file.\n");
    } else {
        MyHandleError("The store has not been saved.");
    }

    // Save the store to a PKCS #7 message in a file.
    // Initialize the BLOB.
    Save_Store_Blob.cbData = 0;
    Save_Store_Blob.pbData = NULL;
    if (CertSaveStore(hCertStore,
                      MY_ENCODING_TYPE,
                      CERT_STORE_SAVE_AS_PKCS7,
                      CERT_STORE_SAVE_TO_MEMORY,
                      (void *)&Save_Store_Blob,
                      0)) {
        printf("The store length, %d, has been determined.\n", Save_Store_Blob.cbData);
    } else {
        MyHandleError("The store length could not be determined.");
    }

    if (Save_Store_Blob.pbData = (BYTE *)malloc(Save_Store_Blob.cbData)) {
        printf("Memory has been allocated.\n");
    } else {
        MyHandleError("Memory allocation failure.");
    }

    if (CertSaveStore(hCertStore,
                      MY_ENCODING_TYPE,
                      CERT_STORE_SAVE_AS_PKCS7,
                      CERT_STORE_SAVE_TO_MEMORY,
                      (void *)&Save_Store_Blob,
                      0)) {
        printf("The store has been saved to memory.\n");
    } else {
        MyHandleError("The store was not saved to memory.");
    }

    //  Retrieve the number of signers of the PKCS #7 message.
    if (dwSignerCount = CryptGetMessageSignerCount(MY_ENCODING_TYPE,
                                                   Save_Store_Blob.pbData,
                                                   Save_Store_Blob.cbData)) {
        printf("The number of signers is %d.\n", dwSignerCount);
    } else {
        printf("The number of signers is zero or could not be found.\n");
    }

    //   Open a certificate store from the PKCS #7 message stored to memory.
    if (hNewStore = CryptGetMessageCertificates(MY_ENCODING_TYPE,
                                                NULL,
                                                0,
                                                Save_Store_Blob.pbData,
                                                Save_Store_Blob.cbData)) {
        printf("A new store has been opened from a PKCS #7.\n");
    } else {
        MyHandleError("Opening the store from the PKCS #7 message failed.");
    }

    //  Next, hash the message.
    //  Store the message and its length in the appropriate arrays.
    rgpbToBeHashed[0] = Save_Store_Blob.pbData;
    rgcbToBeHashed[0] = Save_Store_Blob.cbData;

    //  Initialize the CRYPT_ALGORITHM_IDENTIFIER data structure.
    AlgId.pszObjId = (LPSTR)szOID_RSA_MD5;
    AlgId.Parameters.cbData = 0;

    //  Initialize the CRYPT_HASH_MESSAGE_PARA data structure.
    HashPara.cbSize = sizeof(CRYPT_HASH_MESSAGE_PARA);
    HashPara.dwMsgEncodingType = MY_ENCODING_TYPE;
    HashPara.hCryptProv = NULL;
    HashPara.HashAlgorithm = AlgId;
    HashPara.pvHashAuxInfo = NULL;

    // Calculate the size of the hashed and encoded message. 
    if (CryptHashMessage(&HashPara,
                         FALSE,
                         1,
                         rgpbToBeHashed,
                         rgcbToBeHashed,
                         NULL,
                         &cbHashedBlob,
                         NULL,
                         NULL)) {
        printf("The size of the hashed, encoded message is %d.\n", cbHashedBlob);
    } else {
        MyHandleError("The size of the hash could not be determined.");
    }

    //  Allocated memory for the hashed, encoded BLOB.
    if (pbHashedBlob = (BYTE *)malloc(cbHashedBlob)) {
        printf("Memory allocated for the hashed, encoded BLOB.\n");
    } else {
        MyHandleError("Memory allocation failed.");
    };

    // Hash and encode the message.
    if (CryptHashMessage(&HashPara,
                         FALSE,
                         1,
                         rgpbToBeHashed,
                         rgcbToBeHashed,
                         pbHashedBlob,
                         &cbHashedBlob,
                         NULL,
                         NULL)) {
        printf("The message has been hashed and encoded.\n");
    } else {
        MyHandleError("The message was not hashed. ");
    }

    //  Call CertControlStore the first time with CERT_CONTROL_STORE_NOTIFY_CHANGE.
    if (CertControlStore(
        hCertStore,                    // The store to be controlled
        0,                             // Not used 
        CERT_STORE_CTRL_NOTIFY_CHANGE, // Control action type
        &hEvent))                      // Points to the event handle.
                                       // When a change is detected,
                                       // a signal is written to the space pointed to by hHandle.
    {
        printf("Notify change worked \n");
    } else {
        MyHandleError("Notify change failed. \n");
    }

    // Wait for the store to change.
    fSignal = (WAIT_OBJECT_0 == WaitForSingleObjectEx(
        hEvent,
        1000,               // Number of milliseconds to wait.
                             // Use INFINITE to wait indefinitely for a change.
        FALSE));
    if (fSignal)
        // The store has changed.
        // Call the function a second time with CERT_STORE_CTRL_RESYNC.
        if (CertControlStore(
            hCertStore,               // in, the store to be controlled
            0,                        // in, not used.
            CERT_STORE_CTRL_RESYNC,   // in, control action type
            &hEvent))                 // in, the handle of the event to be rearmed.
            printf("Resynchronization worked. \n");
        else
            MyHandleError("Resynchronization failed.");
    else {
        printf("The store was not changed. \n");
        printf("Resynchronization was not needed. \n");
    }

    // Free memory.
    free(pbHashedBlob);

    if (pvData)
        free(pvData);
    if (CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG)) {
        printf("The store has been closed. \n");
    } else {
        MyHandleError("The store could not be closed.");
    }
    printf("The program ran to completion without error. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Declare callback functions. 
// Definitions of these functions follow main.

static BOOL WINAPI EnumPhyCallback(
    const void * pvSystemStore,
    DWORD dwFlags,
    LPCWSTR pwszStoreName,
    PCERT_PHYSICAL_STORE_INFO pStoreInfo,
    void * pvReserved,
    void * pvArg);

static BOOL WINAPI EnumSysCallback(
    const void * pvSystemStore,
    DWORD dwFlags,
    PCERT_SYSTEM_STORE_INFO pStoreInfo,
    void * pvReserved,
    void * pvArg);

static BOOL WINAPI EnumLocCallback(
    LPCWSTR pwszStoreLocation,
    DWORD dwFlags,
    void * pvReserved,
    void * pvArg);


void ListingSystemAndPhysicalStores(void)
/*
Example C Program: Listing System and Physical Stores
05/31/2018

The following example enumerates the system certificate store locations, the system certificate stores,
and the physical stores associated with each system store.
This example demonstrates the creation of callback functions and callback functions that call other callback functions.

This example illustrates the following CryptoAPI functions:

CertEnumSystemStoreLocation
CertEnumSystemStore
This example also uses the function MyHandleError. Code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-listing-system-and-physical-stores
*/
{
    // Declare and initialize variables.
    DWORD dwExpectedError = 0;
    DWORD dwLocationID = CERT_SYSTEM_STORE_CURRENT_USER_ID;
    DWORD dwFlags = 0;
    CERT_PHYSICAL_STORE_INFO PhyStoreInfo;
    ENUM_ARG EnumArg;
    LPSTR pszStoreParameters = NULL;
    LPWSTR pwszStoreParameters = NULL;
    LPWSTR pwszSystemName = NULL;
    LPWSTR pwszPhysicalName = NULL;
    LPWSTR pwszStoreLocationPara = NULL;
    void * pvSystemName;
    void * pvStoreLocationPara;
    DWORD dwNameCnt = 0;
    LPCSTR pszTestName;
    HKEY hKeyRelocate = HKEY_CURRENT_USER;
    LPSTR pszRelocate = NULL;
    HKEY hKeyBase = NULL;

    //  Initialize data structure variables.
    memset(&PhyStoreInfo, 0, sizeof(PhyStoreInfo));
    PhyStoreInfo.cbSize = sizeof(PhyStoreInfo);
    PhyStoreInfo.pszOpenStoreProvider = (LPSTR)sz_CERT_STORE_PROV_SYSTEM_W;
    pszTestName = "Enum";
    pvSystemName = pwszSystemName;
    pvStoreLocationPara = pwszStoreLocationPara;

    memset(&EnumArg, 0, sizeof(EnumArg));
    EnumArg.dwFlags = dwFlags;
    EnumArg.hKeyBase = hKeyBase;

    EnumArg.pvStoreLocationPara = pvStoreLocationPara;
    EnumArg.fAll = TRUE;
    dwFlags &= ~CERT_SYSTEM_STORE_LOCATION_MASK;
    dwFlags |= (dwLocationID << CERT_SYSTEM_STORE_LOCATION_SHIFT) & CERT_SYSTEM_STORE_LOCATION_MASK;

    printf("Begin enumeration of store locations. \n");
    if (CertEnumSystemStoreLocation(dwFlags, &EnumArg, EnumLocCallback)) {
        printf("\nFinished enumerating locations. \n");
    } else {
        MyHandleError("Enumeration of locations failed.");
    }
    printf("\nBegin enumeration of system stores. \n");

    if (CertEnumSystemStore(dwFlags, pvStoreLocationPara, &EnumArg, EnumSysCallback)) {
        printf("\nFinished enumerating system stores. \n");
    } else {
        MyHandleError("Enumeration of system stores failed.");
    }

    printf("\n\nEnumerate the physical stores for the MY system store. \n");
    if (CertEnumPhysicalStore(L"MY", dwFlags, &EnumArg, EnumPhyCallback)) {
        printf("Finished enumeration of the physical stores. \n");
    } else {
        MyHandleError("Enumeration of physical stores failed.");
    }
}


static BOOL GetSystemName(const void * pvSystemStore,
                          DWORD dwFlags,
                          PENUM_ARG pEnumArg,
                          LPCWSTR * ppwszSystemName)
{
    // Declare local variables.
    *ppwszSystemName = NULL;

    if (pEnumArg->hKeyBase && 0 == (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG)) {
        printf("Failed => RELOCATE_FLAG not set in callback. \n");
        return FALSE;
    } else {
        if (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG) {
            PCERT_SYSTEM_STORE_RELOCATE_PARA pRelocatePara;
            if (!pEnumArg->hKeyBase) {
                MyHandleError("Failed => RELOCATE_FLAG is set in callback");
            }
            pRelocatePara = (PCERT_SYSTEM_STORE_RELOCATE_PARA)pvSystemStore;
            if (pRelocatePara->hKeyBase != pEnumArg->hKeyBase) {
                MyHandleError("Wrong hKeyBase passed to callback");
            }
            *ppwszSystemName = pRelocatePara->pwszSystemStore;
        } else {
            *ppwszSystemName = (LPCWSTR)pvSystemStore;
        }
    }

    return TRUE;
}


static BOOL WINAPI EnumPhyCallback(
    const void * pvSystemStore,
    DWORD dwFlags,
    LPCWSTR pwszStoreName,
    PCERT_PHYSICAL_STORE_INFO pStoreInfo,
    void * pvReserved,
    void * pvArg
)
// Define the callback functions.
{
    //  Declare and initialize local variables.
    PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;
    LPCWSTR pwszSystemStore;

    //  Begin callback process.
    if (GetSystemName(pvSystemStore, dwFlags, pEnumArg, &pwszSystemStore)) {
        printf("    %S", pwszStoreName);
    } else {
        MyHandleError("GetSystemName failed.");
    }

    if (pEnumArg->fVerbose && (dwFlags & CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG))
        printf(" (implicitly created)");

    printf("\n");
    return TRUE;
}


static BOOL WINAPI EnumSysCallback(const void * pvSystemStore,
                                   DWORD dwFlags,
                                   PCERT_SYSTEM_STORE_INFO pStoreInfo,
                                   void * pvReserved,
                                   void * pvArg
)
//  Begin callback process.
{
    //  Declare and initialize local variables.
    PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;
    LPCWSTR pwszSystemStore;
    static int line_counter = 0;
    char x;

    //  Begin processing.

    //   Control break. If 5 or more lines have been printed, pause and reset the line counter.
    if (line_counter++ > 5) {
        printf("Enumeration of system store: Press Enter to continue.");
        scanf_s("%c", &x);
        line_counter = 0;
    }

    //  Prepare and display the next detail line.
    if (GetSystemName(pvSystemStore, dwFlags, pEnumArg, &pwszSystemStore)) {
        printf("  %S\n", pwszSystemStore);
    } else {
        MyHandleError("GetSystemName failed.");
    }
    if (pEnumArg->fAll || pEnumArg->fVerbose) {
        dwFlags &= CERT_SYSTEM_STORE_MASK;
        dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_MASK;
        if (!CertEnumPhysicalStore(pvSystemStore, dwFlags, pEnumArg, EnumPhyCallback)) {
            DWORD dwErr = GetLastError();
            if (!(ERROR_FILE_NOT_FOUND == dwErr || ERROR_NOT_SUPPORTED == dwErr)) {
                printf("    CertEnumPhysicalStore");
            }
        }
    }

    return TRUE;
}


static BOOL WINAPI EnumLocCallback(LPCWSTR pwszStoreLocation, DWORD dwFlags, void * pvReserved, void * pvArg)
{
    //  Declare and initialize local variables.
    PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;
    DWORD dwLocationID = (dwFlags & CERT_SYSTEM_STORE_LOCATION_MASK) >> CERT_SYSTEM_STORE_LOCATION_SHIFT;
    static int linecount = 0;
    char x;

    //  Begin processing.

    // Break if more than 5 lines have been printed.
    if (linecount++ > 5) {
        printf("Enumeration of store locations: Press Enter to continue.");
        scanf_s("%c", &x);
        linecount = 0;
    }

    //  Prepare and display the next detail line.
    printf("======   %S   ======\n", pwszStoreLocation);
    if (pEnumArg->fAll) {
        dwFlags &= CERT_SYSTEM_STORE_MASK;
        dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;
        CertEnumSystemStore(dwFlags, (void *)pEnumArg->pvStoreLocationPara, pEnumArg, EnumSysCallback);
    }

    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI EnumCatAttributes(_In_ LPWSTR FilePath)
/*
The following example shows the correct sequence of assignments for the pPrevAttr parameter (pAttr).

参数说明：
A pointer to a null-terminated string that contains the path of the CDF file to open。
也都是.cdf文件。
这样的文件不常见，所以这个函数也不常用。

https://docs.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatcdfenumcatattributes
*/
{
    CRYPTCATCDF * pCDF = CryptCATCDFOpen(FilePath, NULL);
    if (NULL == pCDF) {
        return;
    }

    CRYPTCATATTRIBUTE * pAttr = NULL;

    while (pAttr = CryptCATCDFEnumCatAttributes(pCDF, pAttr, NULL)) {
        //do something with pAttr
    }

    CryptCATCDFClose(pCDF);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
