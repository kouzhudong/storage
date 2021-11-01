#include "pch.h"
#include "Encrypt.h"


#pragma warning(disable:6001)
#pragma warning(disable:26451)
#pragma warning(disable:28182)
#pragma warning(disable:28183)
#pragma warning(disable:6387)
#pragma warning(disable:6386)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Encrypting and Decrypting
2018/05/31

The following sections deal with encrypting messages and files:

Manual Session Key Exchanges
Encrypting a Message
Decrypting a Message
Example C Program: Using CryptEncryptMessage and CryptDecryptMessage
Example C Program: Using CryptProtectData
Example C Program: Encrypting a File
Example C Program: Decrypting a File
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Example of encrypting data and creating an enveloped 
// message using CryptEncryptMessage.


// This program uses the function GetRecipientCert, declared here and defined after main.
PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore);


// This program uses the function DecryptMessage, declared here and defined after main.
BOOL DecryptMessage(BYTE * pbEncryptedBlob,
                    DWORD cbEncryptedBlob,
                    HCRYPTPROV hCryptProv,
                    HCERTSTORE hStoreHandle);


void CryptEncryptMessageTest()
/*
Example C Program: Using CryptEncryptMessage and CryptDecryptMessage

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-using-cryptencryptmessage-and-cryptdecryptmessage
*/
{
    // Declare and initialize variables. This includes getting a pointer 
    // to the message to be encrypted. This code creates a message
    // and gets a pointer to it. In reality, the message content 
    // usually exists somewhere and a pointer to the message is passed to the application. 

    BYTE * pbContent = (BYTE *)"Security is our business.";// The message
    DWORD cbContent = (DWORD)strlen((char *)pbContent) + 1;// Size of message
    HCRYPTPROV hCryptProv;                      // CSP handle
    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pRecipientCert;
    PCCERT_CONTEXT RecipientCertArray[1];
    DWORD EncryptAlgSize;
    CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
    CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;
    DWORD EncryptParamsSize;
    BYTE * pbEncryptedBlob;
    DWORD    cbEncryptedBlob;

    //  Begin processing.
    printf("About to begin with the message %s.\n", pbContent);
    printf("The message length is %d bytes. \n", cbContent);

    // Get a handle to a cryptographic provider.
    if (CryptAcquireContext(
        &hCryptProv,        // Address for handle to be returned.
        NULL,               // Use the current user's logon name.
        NULL,               // Use the default provider.
        PROV_RSA_FULL,      // Need to both encrypt and sign.
        NULL))              // No flags needed.
    {
        printf("A CSP has been acquired. \n");
    } else {
        MyHandleError("Cryptographic context could not be acquired.");
    }

    // Open a system certificate store.
    if (hStoreHandle = CertOpenSystemStoreA(hCryptProv, "MY")) {
        printf("The MY store is open. \n");
    } else {
        MyHandleError("Error getting store handle.");
    }

    // Get a pointer to the recipient's certificate.
    // by calling GetRecipientCert. 
    if (pRecipientCert = GetRecipientCert(hStoreHandle)) {
        printf("A recipient's certificate has been acquired. \n");
    } else {
        printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
        printf("property and an AT_KEYEXCHANGE private key available. \n");
        printf("While the message could be encrypted, in this case, \n");
        printf("it could not be decrypted in this program. \n");
        printf("For more information, see the documentation for \n");
        printf("CryptEncryptMessage and CryptDecryptMessage.\n\n");
        MyHandleError("No Certificate with AT_KEYEXCHANGE key in store.");
    }

    RecipientCertArray[0] = pRecipientCert;// Create a RecipientCertArray.    
    EncryptAlgSize = sizeof(EncryptAlgorithm);// Initialize the algorithm identifier structure.    
    memset(&EncryptAlgorithm, 0, EncryptAlgSize);// Initialize the structure to zero.    
    EncryptAlgorithm.pszObjId = (LPSTR)szOID_RSA_RC4;// Set the necessary member.

    // Initialize the CRYPT_ENCRYPT_MESSAGE_PARA structure. 
    EncryptParamsSize = sizeof(EncryptParams);
    memset(&EncryptParams, 0, EncryptParamsSize);
    EncryptParams.cbSize = EncryptParamsSize;
    EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    EncryptParams.hCryptProv = hCryptProv;
    EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

    // Call CryptEncryptMessage.
    if (CryptEncryptMessage(&EncryptParams,
                            1,
                            RecipientCertArray,
                            pbContent,
                            cbContent,
                            NULL,
                            &cbEncryptedBlob)) {
        printf("The encrypted message is %d bytes. \n", cbEncryptedBlob);
    } else {
        MyHandleError("Getting EncryptedBlob size failed.");
    }

    // Allocate memory for the returned BLOB.
    if (pbEncryptedBlob = (BYTE *)malloc(cbEncryptedBlob)) {
        printf("Memory has been allocated for the encrypted BLOB. \n");
    } else {
        MyHandleError("Memory allocation error while encrypting.");
    }

    // Call CryptEncryptMessage again to encrypt the content.
    if (CryptEncryptMessage(
        &EncryptParams,
        1,
        RecipientCertArray,
        pbContent,
        cbContent,
        pbEncryptedBlob,
        &cbEncryptedBlob)) {
        printf("Encryption succeeded. \n");
    } else {
        MyHandleError("Encryption failed.");
    }

    // Call the function DecryptMessage, whose code follows main, to decrypt the message.
    if (DecryptMessage(pbEncryptedBlob, cbEncryptedBlob, hCryptProv, hStoreHandle)) {
        printf("Decryption succeeded. \n");
    } else {
        printf("Decryption failed. \n");
    }

    // Clean up memory.
    CertFreeCertificateContext(pRecipientCert);
    if (CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG)) {
        printf("The MY store was closed without incident. \n");
    } else {
        printf("Store closed after encryption -- \n"
               "but not all certificates or CRLs were freed. \n");
    }
    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
        printf("The CSP has been released. \n");
    } else {
        printf("CSP was NULL. \n");
    }
}


BOOL DecryptMessage(BYTE * pbEncryptedBlob,
                    DWORD cbEncryptedBlob,
                    HCRYPTPROV hCryptProv,
                    HCERTSTORE hStoreHandle
)
//  Define the function DecryptMessage.

    // Example function for decrypting an encrypted message using CryptDecryptMessage.
    // Its parameters are pbEncryptedBlob, an encrypted message;
    // cbEncryptedBlob, the length of that message;
    // hCryptProv, a CSP; and hStoreHandle, the handle of an open certificate store.
{
    // Declare and initialize local variables.
    DWORD cbDecryptedMessage;
    char * EncryptedString = new char[(cbEncryptedBlob * 2) + 1];
    HCERTSTORE CertStoreArray[] = {hStoreHandle};
    CRYPT_DECRYPT_MESSAGE_PARA  DecryptParams;
    DWORD  DecryptParamsSize = sizeof(DecryptParams);
    BYTE * pbDecryptedMessage;
    LPSTR  DecryptedString;
    BOOL   fReturn = TRUE;

    // Get a pointer to the encrypted message, pbEncryptedBlob, and its length, cbEncryptedBlob.
    // In this example, these are passed as parameters along with a CSP and an open store handle.

    // View the encrypted BLOB.
    // Call a function, ByteToStr, to convert the byte BLOB to ASCII hexadecimal format. 

    ByteToStr(cbEncryptedBlob, pbEncryptedBlob, EncryptedString);

    // Print the converted string.
    printf("The encrypted string is: \n%s\n", EncryptedString);

    //   In this example, the handle to the MY store was passed in as a parameter. 

    //   Create a "CertStoreArray."
    //   In this example, this step was done in the declaration
    //   and initialization of local variables because the store handle 
    //   was passed into the function as a parameter.

    //   Initialize the CRYPT_DECRYPT_MESSAGE_PARA structure.
    memset(&DecryptParams, 0, DecryptParamsSize);
    DecryptParams.cbSize = DecryptParamsSize;
    DecryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    DecryptParams.cCertStore = 1;
    DecryptParams.rghCertStore = CertStoreArray;

    //  Decrypt the message data.
    //  Call CryptDecryptMessage to get the returned data size.
    if (CryptDecryptMessage(
        &DecryptParams,
        pbEncryptedBlob,
        cbEncryptedBlob,
        NULL,
        &cbDecryptedMessage,
        NULL)) {
        printf("The size for the decrypted message is: %d.\n", cbDecryptedMessage);
    } else {
        MyHandleError("Error getting decrypted message size");
    }

    // Allocate memory for the returned decrypted data.
    if (pbDecryptedMessage = (BYTE *)malloc(cbDecryptedMessage)) {
        printf("Memory has been allocated for the decrypted message. \n");
    } else {
        MyHandleError("Memory allocation error while decrypting");
    }

    // Call CryptDecryptMessage to decrypt the data.
    if (CryptDecryptMessage(
        &DecryptParams,
        pbEncryptedBlob,
        cbEncryptedBlob,
        pbDecryptedMessage,
        &cbDecryptedMessage,
        NULL)) {
        DecryptedString = (LPSTR)pbDecryptedMessage;
        printf("Message Decrypted Successfully. \n");
        printf("The decrypted string is: %s\n", DecryptedString);
    } else {
        printf("Error decrypting the message \n");
        printf("Error code %x \n", GetLastError());
        fReturn = FALSE;
    }

    // Clean up memory.
    free(pbEncryptedBlob);
    free(pbDecryptedMessage);
    return fReturn;
}  // End of DecryptMessage


PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore)
// GetRecipientCert enumerates the certificates in a store and finds
// the first certificate that has an AT_EXCHANGE key.  
// If a certificate is found, a pointer to that certificate is returned. 
// Parameter passed in: 
// hCertStore, the handle of the store to be searched. 
{
    // Declare and initialize local variables. 
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fMore = TRUE;
    DWORD dwSize = NULL;
    CRYPT_KEY_PROV_INFO * pKeyInfo = NULL;
    DWORD PropId = CERT_KEY_PROV_INFO_PROP_ID;

    // Find certificates in the store until the end of the store 
    // is reached or a certificate with an AT_KEYEXCHANGE key is found. 

    while (fMore && (pCertContext = CertFindCertificateInStore(
        hCertStore, // Handle of the store to be searched. 
        0,          // Encoding type. Not used for this search. 
        0,          // dwFindFlags. Special find criteria. 
                    // Not used in this search. 
        CERT_FIND_PROPERTY,
        // Find type. Determines the kind of search 
        // to be done. In this case, search for 
        // certificates that have a specific extended property. 
        &PropId,    // pvFindPara. Gives the specific 
                    // value searched for, here the identifier of an extended property. 
        pCertContext)))
        // pCertContext is NULL for the first call to the function. 
        // If the function were being called in a loop, after the first call 
        // pCertContext would be the pointer returned by the previous call. 
    {
        // For simplicity, this code only searches 
        // for the first occurrence of an AT_KEYEXCHANGE key. 
        // In many situations, a search would also look for a 
        // specific subject name as well as the key type. 

        // Call CertGetCertificateContextProperty once to get the returned structure size. 
        if (!(CertGetCertificateContextProperty(
            pCertContext,
            CERT_KEY_PROV_INFO_PROP_ID,
            NULL, &dwSize))) {
            MyHandleError("Error getting key property.");
        }

        // Allocate memory for the returned structure. 
        if (pKeyInfo)
            free(pKeyInfo);
        if (!(pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize))) {
            MyHandleError("Error allocating memory for pKeyInfo.");
        }

        // Get the key information structure. 
        if (!(CertGetCertificateContextProperty(
            pCertContext,
            CERT_KEY_PROV_INFO_PROP_ID,
            pKeyInfo,
            &dwSize))) {
            MyHandleError("The second call to the function failed.");
        }

        // Check the dwKeySpec member for an exchange key. 
        if (pKeyInfo->dwKeySpec == AT_KEYEXCHANGE) {
            fMore = FALSE;
        }
    }    // End of while loop 

    if (pKeyInfo)
        free(pKeyInfo);

    return (pCertContext);
} // End of GetRecipientCert


//////////////////////////////////////////////////////////////////////////////////////////////////


void UsingCryptProtectData()
/*
Example C Program: Using CryptProtectData
2018/05/31

The following example encrypts and decrypts a data BLOB using CryptProtectData and CryptUnprotectData.

This example illustrates the following tasks and CryptoAPI functions:

Initializing a CRYPTPROTECT_PROMPTSTRUCT data structure.
Using CryptProtectData to encrypt a data BLOB.
Using CryptUnprotectData to decrypt the data.
Using LocalFree to release allocated memory.
This example uses the MyHandleError function.
The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

The following example shows protecting data.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-using-cryptprotectdata
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Encrypt data from DATA_BLOB DataIn to DATA_BLOB DataOut.
    // Then decrypt to DATA_BLOB DataVerify.

    // Declare and initialize variables.
    DATA_BLOB DataIn;
    DATA_BLOB DataOut;
    DATA_BLOB DataVerify;
    BYTE * pbDataInput = (BYTE *)"Hello world of data protection.";
    DWORD cbDataInput = (DWORD)strlen((char *)pbDataInput) + 1;
    DataIn.pbData = pbDataInput;
    DataIn.cbData = cbDataInput;
    CRYPTPROTECT_PROMPTSTRUCT PromptStruct;
    LPWSTR pDescrOut = NULL;

    //  Begin processing.
    printf("The data to be encrypted is: %s\n", pbDataInput);

    //  Initialize PromptStruct.
    ZeroMemory(&PromptStruct, sizeof(PromptStruct));
    PromptStruct.cbSize = sizeof(PromptStruct);
    PromptStruct.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_PROTECT;
    PromptStruct.szPrompt = L"This is a user prompt.";

    //  Begin protect phase.
    if (CryptProtectData(
        &DataIn,
        L"This is the description string.", // A description string. 
        NULL,                               // Optional entropy
                                            // not used.
        NULL,                               // Reserved.
        &PromptStruct,                      // Pass a PromptStruct.
        0,
        &DataOut)) {
        printf("The encryption phase worked. \n");
    } else {
        MyHandleError("Encryption error!");
    }

    //   Begin unprotect phase.
    if (CryptUnprotectData(
        &DataOut,
        &pDescrOut,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        &PromptStruct,        // Optional PromptStruct
        0,
        &DataVerify)) {
        printf("The decrypted data is: %s\n", DataVerify.pbData);
        printf("The description of the data was: %S\n", pDescrOut);
    } else {
        MyHandleError("Decryption error!");
    }

    // At this point, memcmp could be used to compare DataIn.pbData and DataVerify.pbDate for equality. 
    // If the two functions worked correctly, the two byte strings are identical. 

    //  Clean up.
    LocalFree(pDescrOut);
    LocalFree(DataOut.pbData);
    LocalFree(DataVerify.pbData);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


bool MyEncryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword)
// Code for the function MyEncryptFile called by main.
// Parameters passed are:
//  pszSource, the name of the input, a plaintext file.
//  pszDestination, the name of the output, an encrypted file to be created.
//  pszPassword, either NULL if a password is not to be used or the string that is the password.
{
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY hXchgKey = NULL;
    HCRYPTHASH hHash = NULL;
    PBYTE pbKeyBlob = NULL;
    DWORD dwKeyBlobLen;
    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount;
    bool fEOF = FALSE;

    // Open the source file. 
    hSourceFile = CreateFile(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile) {
        _tprintf(TEXT("The source plaintext file, %s, is open. \n"), pszSourceFile);
    } else {
        MyHandleError(TEXT("Error opening source plaintext file!\n"), GetLastError());
        goto Exit_MyEncryptFile;
    }

    // Open the destination file. 
    hDestinationFile = CreateFile(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile) {
        _tprintf(TEXT("The destination file, %s, is open. \n"), pszDestinationFile);
    } else {
        MyHandleError(TEXT("Error opening destination file!\n"), GetLastError());
        goto Exit_MyEncryptFile;
    }

    // Get the handle to the default provider. 
    if (CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
        _tprintf(TEXT("A cryptographic provider has been acquired. \n"));
    } else {
        MyHandleError(TEXT("Error during CryptAcquireContext!\n"), GetLastError());
        goto Exit_MyEncryptFile;
    }

    // Create the session key.
    if (!pszPassword || !pszPassword[0]) {
        // No password was passed.
        // Encrypt the file with a random session key, and write the key to a file. 

        // Create a random session key. 
        if (CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH | CRYPT_EXPORTABLE, &hKey)) {
            _tprintf(TEXT("A session key has been created. \n"));
        } else {
            MyHandleError(TEXT("Error during CryptGenKey. \n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        // Get the handle to the exchange public key. 
        if (CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hXchgKey)) {
            _tprintf(TEXT("The user public key has been retrieved. \n"));
        } else {
            if (NTE_NO_KEY == GetLastError()) {
                // No exchange key exists. Try to create one.
                if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hXchgKey)) {
                    MyHandleError(TEXT("Could not create a user public key.\n"), GetLastError());
                    goto Exit_MyEncryptFile;
                }
            } else {
                MyHandleError(TEXT("User public key is not available and may ")
                              TEXT("not exist.\n"), GetLastError());
                goto Exit_MyEncryptFile;
            }
        }

        // Determine size of the key BLOB, and allocate memory. 
        if (CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, NULL, &dwKeyBlobLen)) {
            _tprintf(TEXT("The key BLOB is %d bytes long. \n"), dwKeyBlobLen);
        } else {
            MyHandleError(TEXT("Error computing BLOB length! \n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        if (pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen)) {
            _tprintf(TEXT("Memory is allocated for the key BLOB. \n"));
        } else {
            MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
            goto Exit_MyEncryptFile;
        }

        // Encrypt and export the session key into a simple key BLOB. 
        if (CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {
            _tprintf(TEXT("The key has been exported. \n"));
        } else {
            MyHandleError(TEXT("Error during CryptExportKey!\n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        // Release the key exchange key handle. 
        if (hXchgKey) {
            if (!(CryptDestroyKey(hXchgKey))) {
                MyHandleError(TEXT("Error during CryptDestroyKey.\n"), GetLastError());
                goto Exit_MyEncryptFile;
            }

            hXchgKey = 0;
        }

        // Write the size of the key BLOB to the destination file. 
        if (!WriteFile(hDestinationFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL)) {
            MyHandleError(TEXT("Error writing header.\n"), GetLastError());
            goto Exit_MyEncryptFile;
        } else {
            _tprintf(TEXT("A file header has been written. \n"));
        }

        // Write the key BLOB to the destination file. 
        if (!WriteFile(hDestinationFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL)) {
            MyHandleError(TEXT("Error writing header.\n"), GetLastError());
            goto Exit_MyEncryptFile;
        } else {
            _tprintf(TEXT("The key BLOB has been written to the ")
                     TEXT("file. \n"));
        }

        free(pbKeyBlob);// Free memory.
    } else {
        // The file will be encrypted with a session key derived from a password.
        // The session key will be recreated when the file is 
        // decrypted only if the password used to create the key is available. 

        // Create a hash object. 
        if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
            _tprintf(TEXT("A hash object has been created. \n"));
        } else {
            MyHandleError(TEXT("Error during CryptCreateHash!\n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        // Hash the password. 
        if (CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword), 0)) {
            _tprintf(TEXT("The password has been added to the hash. \n"));
        } else {
            MyHandleError(TEXT("Error during CryptHashData. \n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        // Derive a session key from the hash object. 
        if (CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey)) {
            _tprintf(TEXT("An encryption key is derived from the ")
                     TEXT("password hash. \n"));
        } else {
            MyHandleError(TEXT("Error during CryptDeriveKey!\n"), GetLastError());
            goto Exit_MyEncryptFile;
        }
    }

    // The session key is now ready. If it is not a key derived from 
    // a  password, the session key encrypted with the private key 
    // has been written to the destination file.

    // Determine the number of bytes to encrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE.
    // ENCRYPT_BLOCK_SIZE is set by a #define statement.
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    // Determine the block size. If a block cipher is used, it must have room for an extra block. 
    if (ENCRYPT_BLOCK_SIZE > 1) {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    } else {
        dwBufferLen = dwBlockLen;
    }

    // Allocate memory. 
    if (pbBuffer = (BYTE *)malloc(dwBufferLen)) {
        _tprintf(TEXT("Memory has been allocated for the buffer. \n"));
    } else {
        MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
        goto Exit_MyEncryptFile;
    }

    // In a do loop, encrypt the source file, and write to the source file.     
    do {
        // Read up to dwBlockLen bytes from the source file. 
        if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL)) {
            MyHandleError(TEXT("Error reading plaintext!\n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        if (dwCount < dwBlockLen) {
            fEOF = TRUE;
        }

        // Encrypt data. 
        if (!CryptEncrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBufferLen)) {
            MyHandleError(TEXT("Error during CryptEncrypt. \n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        // Write the encrypted data to the destination file. 
        if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL)) {
            MyHandleError(TEXT("Error writing ciphertext.\n"), GetLastError());
            goto Exit_MyEncryptFile;
        }

        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination file.
    } while (!fEOF);

    fReturn = true;

Exit_MyEncryptFile:
    // Close files.
    if (hSourceFile) {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile) {
        CloseHandle(hDestinationFile);
    }

    // Free memory. 
    if (pbBuffer) {
        free(pbBuffer);
    }

    // Release the hash object. 
    if (hHash) {
        if (!(CryptDestroyHash(hHash))) {
            MyHandleError(TEXT("Error during CryptDestroyHash.\n"), GetLastError());
        }

        hHash = NULL;
    }

    // Release the session key. 
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            MyHandleError(TEXT("Error during CryptDestroyKey!\n"), GetLastError());
        }
    }

    // Release the provider handle. 
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0))) {
            MyHandleError(TEXT("Error during CryptReleaseContext!\n"), GetLastError());
        }
    }

    return fReturn;
} // End Encryptfile.


int EncryptingFile(int argc, _TCHAR * argv[])
/*
Example C Program: Encrypting a File
2018/05/31

The following example encrypts a data file.
The example interactively requests the name of the file that contains plaintext to be encrypted and
the name of a file where the encrypted data is to be written.

The example prompts the user for the names of an input file and an output file.
It also prompts the user for whether a password is to be used to create the encryption session key.
If a password is to be used in the encryption of the data,
the same password must be used in the program that decrypts the file.
For more information, see Example C Program: Decrypting a File.

Due to changing export control restrictions,
the default cryptographic service provider (CSP) and default key length may change between operating system releases.
It is important that both the encryption and decryption use the same CSP and
that the key length be explicitly set to ensure interoperability on different operating system platforms.

This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-encrypting-a-file
*/
{
    if (argc < 3) {
        _tprintf(TEXT("Usage: <example.exe> <source file> ")
                 TEXT("<destination file> | <password>\n"));
        _tprintf(TEXT("<password> is optional.\n"));
        _tprintf(TEXT("Press any key to exit."));
        (void)_gettch();
        return 1;
    }

    LPTSTR pszSource = argv[1];
    LPTSTR pszDestination = argv[2];
    LPTSTR pszPassword = NULL;

    if (argc >= 4) {
        pszPassword = argv[3];
    }

    // Call EncryptFile to do the actual encryption.
    if (MyEncryptFile(pszSource, pszDestination, pszPassword)) {
        _tprintf(TEXT("Encryption of the file %s was successful. \n"), pszSource);
        _tprintf(TEXT("The encrypted data is in file %s.\n"), pszDestination);
    } else {
        MyHandleError(TEXT("Error encrypting file!\n"), GetLastError());
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


bool MyDecryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword)
// Code for the function MyDecryptFile called by main.
// Parameters passed are:
//  pszSource, the name of the input file, an encrypted file.
//  pszDestination, the name of the output, a plaintext file to be created.
//  pszPassword, either NULL if a password is not to be used or the string that is the password.
{
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    HCRYPTPROV hCryptProv = NULL;

    DWORD dwCount;
    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;

    bool fEOF = false;

    // Open the source file. 
    hSourceFile = CreateFile(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile) {
        _tprintf(TEXT("The source encrypted file, %s, is open. \n"), pszSourceFile);
    } else {
        MyHandleError(TEXT("Error opening source plaintext file!\n"), GetLastError());
        goto Exit_MyDecryptFile;
    }

    // Open the destination file. 
    hDestinationFile = CreateFile(
        pszDestinationFile,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile) {
        _tprintf(TEXT("The destination file, %s, is open. \n"), pszDestinationFile);
    } else {
        MyHandleError(TEXT("Error opening destination file!\n"), GetLastError());
        goto Exit_MyDecryptFile;
    }

    // Get the handle to the default provider. 
    if (CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
        _tprintf(TEXT("A cryptographic provider has been acquired. \n"));
    } else {
        MyHandleError(TEXT("Error during CryptAcquireContext!\n"), GetLastError());
        goto Exit_MyDecryptFile;
    }

    // Create the session key.
    if (!pszPassword || !pszPassword[0]) {
        // Decrypt the file with the saved session key. 
        DWORD dwKeyBlobLen;
        PBYTE pbKeyBlob = NULL;

        // Read the key BLOB length from the source file. 
        if (!ReadFile(hSourceFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL)) {
            MyHandleError(TEXT("Error reading key BLOB length!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        // Allocate a buffer for the key BLOB.
        if (!(pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen))) {
            MyHandleError(TEXT("Memory allocation error.\n"), E_OUTOFMEMORY);
        }

        // Read the key BLOB from the source file. 
        if (!ReadFile(hSourceFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL)) {
            MyHandleError(TEXT("Error reading key BLOB length!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        // Import the key BLOB into the CSP. 
        if (!CryptImportKey(hCryptProv, pbKeyBlob, dwKeyBlobLen, 0, 0, &hKey)) {
            MyHandleError(TEXT("Error during CryptImportKey!/n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        if (pbKeyBlob) {
            free(pbKeyBlob);
        }
    } else {
        // Decrypt the file with a session key derived from a password. 

        // Create a hash object. 
        if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
            MyHandleError(TEXT("Error during CryptCreateHash!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        // Hash in the password data. 
        if (!CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword), 0)) {
            MyHandleError(TEXT("Error during CryptHashData!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        // Derive a session key from the hash object. 
        if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey)) {
            MyHandleError(TEXT("Error during CryptDeriveKey!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }
    }

    // The decryption key is now available, either having been 
    // imported from a BLOB read in from the source file or having been created by using the password. 
    // This point in the program is not reached if the decryption key is not available.

    // Determine the number of bytes to decrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE. 

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    dwBufferLen = dwBlockLen;

    // Allocate memory for the file read buffer. 
    if (!(pbBuffer = (PBYTE)malloc(dwBufferLen))) {
        MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
        goto Exit_MyDecryptFile;
    }

    // Decrypt the source file, and write to the destination file.     
    do {
        // Read up to dwBlockLen bytes from the source file. 
        if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL)) {
            MyHandleError(TEXT("Error reading from source file!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        if (dwCount < dwBlockLen) {
            fEOF = TRUE;
        }

        // Decrypt the block of data. 
        if (!CryptDecrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount)) {
            MyHandleError(TEXT("Error during CryptDecrypt!\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        // Write the decrypted data to the destination file. 
        if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL)) {
            MyHandleError(TEXT("Error writing ciphertext.\n"), GetLastError());
            goto Exit_MyDecryptFile;
        }

        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination file.
    } while (!fEOF);

    fReturn = true;

Exit_MyDecryptFile:

    // Free the file read buffer.
    if (pbBuffer) {
        free(pbBuffer);
    }

    // Close files.
    if (hSourceFile) {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile) {
        CloseHandle(hDestinationFile);
    }

    // Release the hash object. 
    if (hHash) {
        if (!(CryptDestroyHash(hHash))) {
            MyHandleError(TEXT("Error during CryptDestroyHash.\n"), GetLastError());
        }

        hHash = NULL;
    }

    // Release the session key. 
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            MyHandleError(TEXT("Error during CryptDestroyKey!\n"), GetLastError());
        }
    }

    // Release the provider handle. 
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0))) {
            MyHandleError(TEXT("Error during CryptReleaseContext!\n"), GetLastError());
        }
    }

    return fReturn;
}


int DecryptingFile(int argc, _TCHAR * argv[])
/*
Example C Program: Decrypting a File
2018/05/31

The following example shows the decryption of a file.
The example asks the user for the name of an encrypted file and
the name of a file where the decrypted data will be written.
The file with the encrypted data must exist.
The example creates or overwrites the output file.

The example also requests a string that is used as a password.
If a password was used to create the encryption session key,
that same password must be entered to create the decryption session key.
For more information, see Example C Program: Encrypting a File.

Due to changing export control restrictions,
the default cryptographic service provider (CSP) and
default key length may change between operating system releases.
It is important that both the encryption and decryption use the same CSP and
that the key length be explicitly set to ensure interoperability on different operating system platforms.

This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-decrypting-a-file
*/
{
    if (argc < 3) {
        _tprintf(TEXT("Usage: <example.exe> <source file> ")
                 TEXT("<destination file> | <password>\n"));
        _tprintf(TEXT("<password> is optional.\n"));
        _tprintf(TEXT("Press any key to exit."));
        (void)_gettch();
        return 1;
    }

    LPTSTR pszSource = argv[1];
    LPTSTR pszDestination = argv[2];
    LPTSTR pszPassword = NULL;

    if (argc >= 4) {
        pszPassword = argv[3];
    }

    // Call EncryptFile to do the actual encryption.
    if (MyDecryptFile(pszSource, pszDestination, pszPassword)) {
        _tprintf(TEXT("Encryption of the file %s was successful. \n"), pszSource);
        _tprintf(TEXT("The encrypted data is in file %s.\n"), pszDestination);
    } else {
        MyHandleError(TEXT("Error encrypting file!\n"), GetLastError());
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// In this and all other examples, use the #define and
// #include statements listed under #includes and #defines.


// This program uses the function GetSignerCert, declared here and defined after main.
PCCERT_CONTEXT GetSignerCert(HCERTSTORE hCertStore);


void EncodingEnvelopedMessage(void)
/*
Alternate Code for Encoding an Enveloped Message
2018/05/31

The following example demonstrates an alternate process of encoding a signed message,
using that signed message as the inner content for an enveloped message.
In preparation for decoding, the inner content is tested to determine its inner-content type.

This example illustrates the following CryptoAPI functions:

CryptAcquireContext
CertOpenSystemStore
CryptMsgCalculateEncodedLength
CryptMsgOpenToEncode
CryptMsgUpdate
CryptMsgGetParam
CryptMsgOpenToDecode
CertFindCertificateInStore
CryptMsgClose
CertCloseStore
CryptReleaseContext
This example also uses the functions MyHandleError and GetSignerCert.
C code for these functions is included with the example.
For code that demonstrates these and other auxiliary functions, see General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/alternate-code-for-encoding-an-enveloped-message?redirectedfrom=MSDN
*/
{
    // Declare and initialize variables. This includes declaring and 
    // initializing a pointer to message content to be countersigned 
    // and encoded. Usually, the message content will exist somewhere,
    // and a pointer to it is passed to the application. 

    BYTE * pbContent = (BYTE *)"The message to be countersigned.";// The message
    DWORD cbContent;               // Size of message
    HCRYPTPROV hCryptProv;         // CSP handle
    HCERTSTORE hStoreHandle;       // Store handle
    PCCERT_CONTEXT pSignerCert;    // Signer certificate
    DWORD HashAlgSize;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo;
    CMSG_SIGNER_ENCODE_INFO SignerEncodeInfoArray[1];
    CERT_BLOB SignerCertBlob;
    CERT_BLOB SignerCertBlobArray[1];
    CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo;
    DWORD cbEncodedBlob;
    BYTE * pbEncodedBlob;
    HCRYPTMSG hMsg;
    DWORD cbDecoded;
    BYTE * pbDecoded;
    PCCERT_CONTEXT pCntrSigCert;
    CMSG_SIGNER_ENCODE_INFO CountersignerInfo;
    CMSG_SIGNER_ENCODE_INFO CntrSignArray[1];
    DWORD cbSignerInfo;
    PBYTE pbSignerInfo;
    DWORD cbCountersignerInfo;
    PCRYPT_ATTRIBUTES pCountersignerInfo;

    // Begin processing. 
    cbContent = (DWORD)strlen((char *)pbContent) + 1;
    // One is added to include the final NULL character.
    printf("Processing begins.\n");
    printf("The length of the original message is %d.\n", cbContent);
    printf("Example message:->%s\n", pbContent);

    // Get a handle to a cryptographic provider. 
    if (CryptAcquireContext(
        &hCryptProv,        // Address for handle to be returned
        NULL,               // Use the logon name for the current user
        NULL,               // Use the default provider
        PROV_RSA_FULL,      // Provider type
        0))                 // Zero allows access to private keys
    {
        printf("The CSP has been opened.");
    } else {
        MyHandleError("CryptAcquireContext failed");
    }

    // Open the MY system certificate store.
    if (hStoreHandle = CertOpenStore(
        CERT_STORE_PROV_SYSTEM, // The system store will be a virtual store.
        0,                      // Encoding type not needed with this PROV.
        NULL,                   // Accept the default HCRYPTPROV. 
        CERT_SYSTEM_STORE_CURRENT_USER, // Set the system store location in the registry.
        L"MY"))                 // Other predefined system stores 
                                // could have been used, including trust, CA, or root.
    {
        printf("Opened the MY system store. \n");
    } else {
        MyHandleError("Could not open the MY system store.");
    }

    // Get a pointer to the signature certificate of the signer.
    if (pSignerCert = GetSignerCert(hStoreHandle)) {
        printf("A signer certificate was found. \n");
    } else {
        MyHandleError("Error getting signer certificate.");
    }

    // Initialize the algorithm identifier structure.
    HashAlgSize = sizeof(HashAlgorithm);
    memset(&HashAlgorithm, 0, HashAlgSize);  // Initialize to zero,
    HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5;  // then set the 
                                             // necessary member.

    // Initialize the CMSG_SIGNER_ENCODE_INFO structure.
    memset(&SignerEncodeInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    SignerEncodeInfo.pCertInfo = pSignerCert->pCertInfo;
    SignerEncodeInfo.hCryptProv = hCryptProv;
    SignerEncodeInfo.dwKeySpec = AT_KEYEXCHANGE;
    SignerEncodeInfo.HashAlgorithm = HashAlgorithm;
    SignerEncodeInfo.pvHashAuxInfo = NULL;

    // Initialize the first element of an array of signers. 
    // There can be only one signer.
    SignerEncodeInfoArray[0] = SignerEncodeInfo;

    // Initialize the CMSG_SIGNED_ENCODE_INFO structure.
    SignerCertBlob.cbData = pSignerCert->cbCertEncoded;
    SignerCertBlob.pbData = pSignerCert->pbCertEncoded;

    //  Initialize the first element of an array of signer BLOBs.
    //  Only one signer BLOB used.
    SignerCertBlobArray[0] = SignerCertBlob;
    memset(&SignedMsgEncodeInfo, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
    SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
    SignedMsgEncodeInfo.cSigners = 1;
    SignedMsgEncodeInfo.rgSigners = SignerEncodeInfoArray;
    SignedMsgEncodeInfo.cCertEncoded = 1;
    SignedMsgEncodeInfo.rgCertEncoded = SignerCertBlobArray;
    SignedMsgEncodeInfo.rgCrlEncoded = NULL;

    // Get the size of the encoded message BLOB.
    if (cbEncodedBlob = CryptMsgCalculateEncodedLength(
        MY_ENCODING_TYPE,     // Message encoding type
        0,                    // Flags
        CMSG_SIGNED,          // Message type
        &SignedMsgEncodeInfo, // Pointer to structure
        NULL,                 // Inner content OID
        cbContent))           // Size of content
    {
        printf("The size for the encoded BLOB is %d.\n", cbEncodedBlob);
    } else {
        MyHandleError("Getting cbEncodedBlob length failed.");
    }

    // Allocate memory for the encoded BLOB.
    if (pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob)) {
        printf("Memory has been allocated for the BLOB. \n");
    } else {
        MyHandleError("Malloc operation failed.");
    }

    // Open a message to encode.
    if (hMsg = CryptMsgOpenToEncode(
        MY_ENCODING_TYPE,      // Encoding type
        0,                     // Flags
        CMSG_SIGNED,           // Message type
        &SignedMsgEncodeInfo,  // Pointer to structure
        NULL,                  // Inner content OID
        NULL))                 // Stream information (not used)
    {
        printf("The message to encode is open. \n");
    } else {
        MyHandleError("OpenToEncode failed");
    }

    // Update the message with the data.
    if (CryptMsgUpdate(
        hMsg,       // Handle to the message
        pbContent,  // Pointer to the content
        cbContent,  // Size of the content
        TRUE))      // Last call
    {
        printf("Message to encode has been updated. \n");
    } else {
        MyHandleError("MsgUpdate failed");
    }

    // Get the resulting message.
    if (CryptMsgGetParam(
        hMsg,               // Handle to the message
        CMSG_CONTENT_PARAM, // Parameter type
        0,                  // Index
        pbEncodedBlob,      // Pointer to the BLOB
        &cbEncodedBlob))    // Size of the BLOB
    {
        printf("Message successfully signed. \n");
    } else {
        MyHandleError("MsgGetParam failed.");
    }

    // pbEncodedBlob points to the encoded, signed content.
    // Include any further processing here.
    CryptMsgClose(hMsg); // The message is complete--close the handle.

    // Next, countersign the signed message. 
    // Assume that the message just created and that a pointer
    // (pbEncodedBlob) to the message were sent to the intended 
    // recipient.
    // The following code, from the recipient's point of view, adds a 
    // countersignature to the signed message.
    //
    // Before countersigning, the message must be decoded.

    // Open a message for decoding.
    if (hMsg = CryptMsgOpenToDecode(
        MY_ENCODING_TYPE,   // Encoding type
        0,                  // Flags
        0,                  // Message type (get from message)
        hCryptProv,         // Cryptographic provider
        NULL,               // Recipient information
        NULL))              // Stream information
    {
        printf("The message for decoding has been opened. \n");
    } else {
        MyHandleError("OpenToDecode failed.");
    }

    // Update the message with the data (encoded BLOB).
    // In this example, pbEncodedBlob and cbEncodedBlob were created in the previous code.
    if (CryptMsgUpdate(
        hMsg,            // Handle to the message
        pbEncodedBlob,   // Pointer to the encoded BLOB
        cbEncodedBlob,   // Size of the encoded BLOB
        TRUE))           // Last call
    {
        printf("The message to be decoded has been updated. \n");
    } else {
        MyHandleError("Decode MsgUpdate failed.");
    }

    // Get the size of the content.
    if (CryptMsgGetParam(
        hMsg,                    // Handle to the message
        CMSG_CONTENT_PARAM,      // Parameter type
        0,                       // Index
        NULL,                    // Address for returned information
        &cbDecoded))             // Size of the returned information
    {
        printf("The message to be decoded is %d bytes long. \n", cbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM failed");
    }

    // Allocate memory.
    if (pbDecoded = (BYTE *)malloc(cbDecoded)) {
        printf("Memory has been allocated. \n");
    } else {
        MyHandleError("Decode memory allocation failed");
    }

    // Get a pointer to the content.
    if (CryptMsgGetParam(
        hMsg,                // Handle to the message
        CMSG_CONTENT_PARAM,  // Parameter type
        0,                   // Index
        pbDecoded,           // Address for returned information
        &cbDecoded))         // Size of the returned information
    {
        printf("The successfully decoded message is =>%s\n", pbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM #2 failed.");
    }

    // Proceed with the countersigning.

    // Initialize the CRYPT_ALGORITHM_IDENTIFIER structure. In this 
    // case, the initialization performed for signing the message in the previous code is used.

    // Get the certificate of the countersigner. A certificate with a 
    // subject name that matches the string in parameter five must  
    // be in the MY store and must have its CERT_KEY_PROV_INFO_PROP_ID property set.
    if (pCntrSigCert = CertFindCertificateInStore(
        hStoreHandle,
        MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING.
        0,                           // No dwFlags needed. 
        CERT_FIND_SUBJECT_STR,       // Find a certificate with a subject that matches the string
                                     // in the next parameter.
        L"Full Test Cert",           // The Unicode string to be found
                                     // in a certificate's subject.
        NULL))                       // NULL for the first call to the function. In all subsequent
                                     // calls, it is the last pointer returned by the function.
    {
        printf("The desired certificate was found. \n");
    } else {
        MyHandleError("Could not find the countersigner's certificate.");
    }

    // Initialize the PCMSG_SIGNER_ENCODE_INFO structure.
    memset(&CountersignerInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    CountersignerInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    CountersignerInfo.pCertInfo = pCntrSigCert->pCertInfo;
    CountersignerInfo.hCryptProv = hCryptProv;
    CountersignerInfo.dwKeySpec = AT_KEYEXCHANGE;
    CountersignerInfo.HashAlgorithm = HashAlgorithm;

    CntrSignArray[0] = CountersignerInfo;

    // Countersign the message.
    if (CryptMsgCountersign(hMsg, 0, 1, CntrSignArray)) {
        printf("Countersign succeeded. \n");
    } else {
        MyHandleError("Countersign failed.");
    }

    // Get a pointer to the new, countersigned message BLOB.
    // Get the size of memory required.
    if (CryptMsgGetParam(
        hMsg,                  // Handle to the message
        CMSG_ENCODED_MESSAGE,  // Parameter type
        0,                     // Index
        NULL,                  // Address for returned information
        &cbEncodedBlob))       // Size of the returned information
    {
        printf("The size for the encoded BLOB is %d.\n", cbEncodedBlob);
    } else {
        MyHandleError("Sizing of cbSignerInfo failed.");
    }

    // Allocate memory.
    if (pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob)) {
        printf("%d bytes allocated .\n", cbEncodedBlob);
    } else {
        MyHandleError("cbSignerInfo memory allocation failed");
    }

    // Get the new message encoded BLOB.
    if (CryptMsgGetParam(
        hMsg,                   // Handle to the message
        CMSG_ENCODED_MESSAGE,   // Parameter type
        0,                      // Index
        pbEncodedBlob,          // Address for returned information
        &cbEncodedBlob))        // Size of the returned information
    {
        printf("The message is complete. \n");
    } else {
        MyHandleError("Getting pbEncodedBlob failed");
    }

    //  The message is complete. Close the handle.
    CryptMsgClose(hMsg);

    // Verify the countersignature.
    // Assume that the countersigned message went back to the originator, where, again, it will be decoded.

    // Before verifying the countersignature, the message must first be decoded.

    // Open a message for decoding.
    if (hMsg = CryptMsgOpenToDecode(
        MY_ENCODING_TYPE,    // Encoding type
        0,                   // Flags
        0,                   // Message type (get from message)
        hCryptProv,          // Cryptographic provider
        NULL,                // Recipient information
        NULL))               // Stream information
    {
        printf("The message to decode has been opened. \n");
    } else {
        MyHandleError("OpenToDecode failed.");
    }

    // Update the message with the encoded BLOB.
    // In this example, pbEncodedBlob and cbEncodedBlob were initialized in the previous code.

    if (CryptMsgUpdate(
        hMsg,            // Handle to the message
        pbEncodedBlob,   // Pointer to the encoded BLOB
        cbEncodedBlob,   // Size of the encoded BLOB
        TRUE))           // Last call
    {
        printf("The message to decode has been updated. \n");
    } else {
        MyHandleError("Updating of the verified countersignature message failed.");
    }

    // Get a pointer to the CERT_INFO member of the certificate of the  
    // countersigner. In this case, the certificate retrieved in the
    // previous code segment will be used (pCntrSigCert).

    // Retrieve the signer information from the message.
    // Get the size of memory required.

    if (CryptMsgGetParam(
        hMsg,                  // Handle to the message
        CMSG_ENCODED_SIGNER,   // Parameter type
        0,                     // Index
        NULL,                  // Address for returned information
        &cbSignerInfo))        // Size of the returned information
    {
        printf("The size of the signer information has been retrieved.\n");
    } else {
        MyHandleError("Sizing of cbSignerInfo failed.");
    }

    // Allocate memory.
    if (pbSignerInfo = (BYTE *)malloc(cbSignerInfo)) {
        printf("%d bytes allocated for the signer information. \n", cbSignerInfo);
    } else {
        MyHandleError("cbSignerInfo memory allocation failed");
    }

    // Get the message signer information.
    if (CryptMsgGetParam(
        hMsg,                 // Handle to the message
        CMSG_ENCODED_SIGNER,  // Parameter type
        0,                    // Index
        pbSignerInfo,         // Address for returned information
        &cbSignerInfo))       // Size of the returned information
    {
        printf("The signer information is retrieved. \n");
    } else {
        MyHandleError("Getting pbSignerInfo failed.");
    }

    // Retrieve the countersigner information from the message.
    // Get the size of memory required.
    if (CryptMsgGetParam(
        hMsg,                         // Handle to the message
        CMSG_SIGNER_UNAUTH_ATTR_PARAM,// Parameter type
        0,                            // Index
        NULL,                         // Address for returned information
        &cbCountersignerInfo))        // Size of returned information
    {
        printf("The length of the countersigner's information is retrieved. \n");
    } else {
        MyHandleError("Sizing of cbCountersignerInfo failed.");
    }

    // Allocate memory.
    if (pCountersignerInfo = (CRYPT_ATTRIBUTES *)malloc(cbCountersignerInfo)) {
        printf("%d bytes allocated. \n", cbCountersignerInfo);
    } else {
        MyHandleError("pbCountersignInfo memory allocation failed.");
    }

    // Get the message SIGNER_INFO.
    if (CryptMsgGetParam(
        hMsg,                           // Handle to the message
        CMSG_SIGNER_UNAUTH_ATTR_PARAM,  // Parameter type
        0,                              // Index
        pCountersignerInfo,             // Address for returned information
        &cbCountersignerInfo))          // Size of the returned information
    {
        printf("Countersigner information retrieved. \n");
    } else {
        MyHandleError("Getting pbCountersignerInfo failed.");
    }

    // Verify the countersignature.
    if (CryptMsgVerifyCountersignatureEncoded(
        hCryptProv,
        MY_ENCODING_TYPE,
        pbSignerInfo,
        cbSignerInfo,
        pCountersignerInfo->rgAttr->rgValue->pbData,
        pCountersignerInfo->rgAttr->rgValue->cbData,
        pCntrSigCert->pCertInfo)) {
        printf("Verification of countersignature succeeded. \n");
    } else {
        printf("Verification of countersignature failed. \n");
    }

    // Clean up.
    free(pbEncodedBlob);
    free(pbDecoded);
    free(pbSignerInfo);
    free(pCountersignerInfo);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    CryptMsgClose(hMsg);
    CryptReleaseContext(hCryptProv, 0);
}


PCCERT_CONTEXT GetSignerCert(HCERTSTORE hCertStore)
// GetSignerCert enumerates the certificates in a store and
// finds the first certificate that has a signature key. If a 
// certificate is found, a pointer to the certificate is returned.
// Parameter passed in:
// hCertStore, the handle of the store to be searched.
{
    // Declare and initialize local variables.
    PCCERT_CONTEXT       pCertContext = NULL;
    BOOL                 fMore = TRUE;
    DWORD                dwSize = NULL;
    CRYPT_KEY_PROV_INFO * pKeyInfo = NULL;
    DWORD                PropId = CERT_KEY_PROV_INFO_PROP_ID;

    // Find certificates in the store until the end of the store
    // is reached or a certificate with an AT_SIGNATURE key is found.

    while (fMore &&
           (pCertContext = CertFindCertificateInStore(
               hCertStore,           // Handle of the store to be searched.
               0,                    // Encoding type. Not used for this search.
               0,                    // dwFindFlags. Special find criteria.
                                     // Not used in this search.
               CERT_FIND_PROPERTY,   // Find type. Determines the kind of  
                                     // search to be done. In this case, search 
                                     // for certificates that have a specific extended property.
               &PropId,              // pvFindPara. Gives the specific 
                                     // value searched for, here the identifier of an extended property.
               pCertContext)))       // pCertContext is NULL for the 
                                     // first call to the function. 
                                     // If the function were being called in a loop, after the first call,
                                     // pCertContext would be the certificate
                                     // returned by the previous call.
    {
        // For simplicity, this code only searches for the first occurrence of an AT_SIGNATURE key. 
        // In many situations, a search would also look for a specific subject name as well as the key type.

        // Call CertGetCertificateContextProperty once to get the returned structure size.
        if (!(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))) {
            MyHandleError("Error getting key property");
        }

        // Allocate memory for the returned structure.
        if (pKeyInfo)
            free(pKeyInfo);
        if (!(pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize))) {
            MyHandleError("Error allocating memory for pKeyInfo");
        }

        // Get the key information structure.
        if (!(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize))) {
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
}  // End of GetSignerCert.


//////////////////////////////////////////////////////////////////////////////////////////////////


void EncodingEnvelopedSignedMessage(void)
/*
Example C Program: Encoding an Enveloped, Signed Message
2018/05/31

The following example creates, signs, and envelopes a message,
and it illustrates the following tasks and CryptoAPI functions:

Acquiring the handle of a CSP using CryptAcquireContext.
Opening a system store using CertOpenStore.
Finding a signer and recipient certificates using CertFindCertificateInStore.
Initializing appropriate data structures for signing an enveloped message.
Finding the length of the enveloped message using CryptMsgCalculateEncodedLength.
Creating and signs the message using CryptMsgOpenToEncode, CryptMsgUpdate, and CryptMsgGetParam.
Enveloping the signed and encoded message for a receiver using CryptMsgOpenToEncode, CryptMsgUpdate, and CryptMsgGetParam.
This example will fail if a usable private key does not exist in the default key container.
If the needed private key is not available, code using CryptAcquireCertificatePrivateKey,
as demonstrated in the code sample Example C Program: Sending and Receiving a Signed and Encrypted Message, can be used.

This example uses the function MyHandleError.
The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-encoding-an-enveloped-signed-message
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.

    BYTE * pbContent = (BYTE *)"Security is our only business.";// a byte pointer
    DWORD cbContent = (DWORD)strlen((char *)pbContent) + 1;// the size of the message
    HCERTSTORE hStoreHandle;
    HCRYPTPROV hCryptProv;
    PCCERT_CONTEXT pSignerCert;         // signer's certificate
    PCCERT_CONTEXT pRecipCert;          // receiver's certificate
    LPCWSTR pswzRecipientName = L"Hortense";
    LPCWSTR pswzCertSubject = L"Full Test Cert";
    PCERT_INFO RecipCertArray[1];
    DWORD ContentEncryptAlgSize;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptAlgorithm;
    CMSG_ENVELOPED_ENCODE_INFO EnvelopedEncodeInfo;
    DWORD cbEncodedBlob;
    BYTE * pbEncodedBlob;
    DWORD cbSignedBlob;
    BYTE * pbSignedBlob;
    HCRYPTMSG hMsg;
    DWORD HashAlgSize;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo;
    CERT_BLOB SignerCertBlob;
    CERT_BLOB SignerCertBlobArray[1];
    CMSG_SIGNER_ENCODE_INFO SignerEncodeInfoArray[1];
    CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo;

    // Begin processing. Display the original message.
    printf("The original message => %s\n", pbContent);

    // Acquire a cryptographic provider. 
    if (CryptAcquireContext(
        &hCryptProv,      // address for handle to be returned
        NULL,             // use the current user's logon name
        NULL,             // use the default provider
        PROV_RSA_FULL,    // provider type
        0))               // zero allows access to private keys
    {
        printf("Context CSP acquired. \n");
    } else {
        if (GetLastError() == NTE_BAD_KEYSET) {
            printf("A Usable private key was not found \n");
            printf("in the default key container. Either a \n");
            printf("private key must be generated in that container \n");
            printf("or CryptAquireCertificatePrivateKey can be used \n");
            printf("to gain access to the needed private key.");
        }
        MyHandleError("CryptAcquireContext failed.");
    }

    // Open the My system certificate store.
    if (hStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY")) {
        printf("The MY system store is open. \n");
    } else {
        MyHandleError("Error getting store handle.");
    }

    // Get the signer's certificate. This certificate must be in the
    // My store, and its private key must be available.
    if (pSignerCert = CertFindCertificateInStore(
        hStoreHandle,
        MY_ENCODING_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        pswzCertSubject,
        NULL)) {
        printf("Found certificate for %S.\n", pswzCertSubject);
    } else {
        MyHandleError("Signer certificate not found.");
    }

    // Initialize the algorithm identifier structure.
    HashAlgSize = sizeof(HashAlgorithm);
    memset(&HashAlgorithm, 0, HashAlgSize);    // initialize to zero
    HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5;    // initialize the necessary member

    // Initialize the CMSG_SIGNER_ENCODE_INFO structure.
    memset(&SignerEncodeInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    SignerEncodeInfo.pCertInfo = pSignerCert->pCertInfo;
    SignerEncodeInfo.hCryptProv = hCryptProv;
    SignerEncodeInfo.dwKeySpec = AT_KEYEXCHANGE;
    SignerEncodeInfo.HashAlgorithm = HashAlgorithm;
    SignerEncodeInfo.pvHashAuxInfo = NULL;

    // Create an array of one. 
    // Note: The current program is set up for only a single signer.
    SignerEncodeInfoArray[0] = SignerEncodeInfo;

    // Initialize the CMSG_SIGNED_ENCODE_INFO structure.
    SignerCertBlob.cbData = pSignerCert->cbCertEncoded;
    SignerCertBlob.pbData = pSignerCert->pbCertEncoded;

    // Initialize the array of one CertBlob.
    SignerCertBlobArray[0] = SignerCertBlob;
    memset(&SignedMsgEncodeInfo, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
    SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
    SignedMsgEncodeInfo.cSigners = 1;
    SignedMsgEncodeInfo.rgSigners = SignerEncodeInfoArray;
    SignedMsgEncodeInfo.cCertEncoded = 1;
    SignedMsgEncodeInfo.rgCertEncoded = SignerCertBlobArray;
    SignedMsgEncodeInfo.rgCrlEncoded = NULL;

    // Get the size of the encoded, signed message BLOB.
    if (cbSignedBlob = CryptMsgCalculateEncodedLength(
        MY_ENCODING_TYPE,       // message encoding type
        0,                      // flags
        CMSG_SIGNED,            // message type
        &SignedMsgEncodeInfo,   // pointer to structure
        NULL,                   // inner content OID
        cbContent))             // size of content
    {
        printf("%d, the length of data calculated. \n", cbSignedBlob);
    } else {
        if (GetLastError() == NTE_BAD_KEYSET) {
            printf("A Usable private key was not found \n");
            printf("in the default key container. Either a \n");
            printf("private key must be generated in that container \n");
            printf("or CryptAquireCertificatePRivateKey can be used \n");
            printf("to gain access to the needed private key.");
        }
        MyHandleError("Getting cbSignedBlob length failed.");
    }

    // Allocate memory for the encoded BLOB.
    if (pbSignedBlob = (BYTE *)malloc(cbSignedBlob)) {
        printf("Memory has been allocated for the signed message. \n");
    } else {
        MyHandleError("Memory allocation failed.");
    }

    // Open a message to encode.
    if (hMsg = CryptMsgOpenToEncode(
        MY_ENCODING_TYPE,        // encoding type
        0,                       // flags
        CMSG_SIGNED,             // message type
        &SignedMsgEncodeInfo,    // pointer to structure
        NULL,                    // inner content OID
        NULL))                   // stream information (not used)
    {
        printf("The message to be encoded has been opened. \n");
    } else {
        MyHandleError("OpenToEncode failed.");
    }

    // Update the message with the data.
    if (CryptMsgUpdate(
        hMsg,         // handle to the message
        pbContent,    // pointer to the content
        cbContent,    // size of the content
        TRUE))        // last call
    {
        printf("Content has been added to the encoded message. \n");
    } else {
        MyHandleError("MsgUpdate failed.");
    }

    // Get the resulting message.
    if (CryptMsgGetParam(
        hMsg,                      // handle to the message
        CMSG_CONTENT_PARAM,        // parameter type
        0,                         // index
        pbSignedBlob,              // pointer to the BLOB
        &cbSignedBlob))            // size of the BLOB
    {
        printf("Message encoded successfully. \n");
    } else {
        MyHandleError("MsgGetParam failed.");
    }

    // pbSignedBlob now points to the encoded, signed content.

    // Get a pointer to the recipient certificate.
    // For this program, the recipient's certificate must also be in the
    // My store. At this point, only the recipient's public key is needed.
    // To open the enveloped message, however, the recipient's private key must also be available.
    if (pRecipCert = CertFindCertificateInStore(
        hStoreHandle,
        MY_ENCODING_TYPE,            // use X509_ASN_ENCODING
        0,                           // no dwFlags needed
        CERT_FIND_SUBJECT_STR,       // find a certificate with a subject that matches the 
                                     // string in the next parameter
        pswzRecipientName,           // the Unicode string to be found in a certificate's subject
        NULL))                       // NULL for the first call to the function
                                     // in all subsequent calls, it is the last pointer
                                     // returned by the function
    {
        printf("Certificate for %S found. \n", pswzRecipientName);
    } else {
        MyHandleError("Could not find the countersigner's certificate.");
    }

    // Initialize the first element of the array of CERT_INFOs. 
    // In this example, there is only a single recipient.
    RecipCertArray[0] = pRecipCert->pCertInfo;

    // Initialize the symmetric-encryption algorithm identifier structure.
    ContentEncryptAlgSize = sizeof(ContentEncryptAlgorithm);
    memset(&ContentEncryptAlgorithm, 0, ContentEncryptAlgSize);// initialize to zero

    // Initialize the necessary members. This particular OID does not
    // need any parameters. Some OIDs, however, will require that the other members be initialized.
    ContentEncryptAlgorithm.pszObjId = (LPSTR)szOID_RSA_RC4;

    // Initialize the CMSG_ENVELOPED_ENCODE_INFO structure.
    memset(&EnvelopedEncodeInfo, 0, sizeof(CMSG_ENVELOPED_ENCODE_INFO));
    EnvelopedEncodeInfo.cbSize = sizeof(CMSG_ENVELOPED_ENCODE_INFO);
    EnvelopedEncodeInfo.hCryptProv = hCryptProv;
    EnvelopedEncodeInfo.ContentEncryptionAlgorithm = ContentEncryptAlgorithm;
    EnvelopedEncodeInfo.pvEncryptionAuxInfo = NULL;
    EnvelopedEncodeInfo.cRecipients = 1;
    EnvelopedEncodeInfo.rgpRecipients = RecipCertArray;

    // Get the size of the encoded message BLOB.
    if (cbEncodedBlob = CryptMsgCalculateEncodedLength(
        MY_ENCODING_TYPE,        // message encoding type
        0,                       // flags
        CMSG_ENVELOPED,          // message type
        &EnvelopedEncodeInfo,    // pointer to structure
        (LPSTR)szOID_RSA_signedData,    // inner content OID
        cbSignedBlob))           // size of content
    {
        printf("Length of the encoded BLOB will be %d.\n", cbEncodedBlob);
    } else {
        MyHandleError("Getting enveloped cbEncodedBlob length failed.");
    }

    // Allocate memory for the encoded BLOB.
    if (pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob)) {
        printf("Memory has been allocated for the BLOB. \n");
    } else {
        MyHandleError("Enveloped malloc operation failed.");
    }

    // Open a message to encode.
    if (hMsg = CryptMsgOpenToEncode(
        MY_ENCODING_TYPE,        // encoding type
        0,                       // flags
        CMSG_ENVELOPED,          // message type
        &EnvelopedEncodeInfo,    // pointer to structure
        (LPSTR)szOID_RSA_signedData,    // inner content OID
        NULL))                   // stream information (not used)
    {
        printf("The message to encode is open. \n");
    } else {
        MyHandleError("Enveloped OpenToEncode failed.");
    }

    // Update the message with the data.
    if (CryptMsgUpdate(
        hMsg,              // handle to the message
        pbSignedBlob,      // pointer to the signed data BLOB
        cbSignedBlob,      // size of the data BLOB
        TRUE))             // last call
    {
        printf("The signed BLOB has been added to the message. \n");
    } else {
        MyHandleError("Enveloped MsgUpdate failed.");
    }

    // Get the resulting message.
    if (CryptMsgGetParam(
        hMsg,                  // handle to the message
        CMSG_CONTENT_PARAM,    // parameter type
        0,                     // index
        pbEncodedBlob,         // pointer to the enveloped, signed data BLOB
        &cbEncodedBlob))       // size of the BLOB
    {
        printf("Enveloped message encoded successfully. \n");
    } else {
        MyHandleError("Enveloped MsgGetParam failed.");
    }

    // Clean up.
    CertFreeCertificateContext(pRecipCert);
    if (CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG)) {
        printf("The certificate store closed without a certificate left open. \n");
    } else {
        printf("The store closed but a certificate was still open. \n");
    }

    if (hMsg)
        CryptMsgClose(hMsg);

    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
void WINAPI EnumProvidersByCrypt()
/*
The following example shows a loop listing all available cryptographic service providers.

https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumprovidersa
*/
/*
测试效果：对比ICspInformations的枚举，这里没有CNG，只是Legacy。
Listing Available Providers:
Provider type   Provider Name
_____________   _____________________________________
        1       Microsoft Base Cryptographic Provider v1.0
       13       Microsoft Base DSS and Diffie-Hellman Cryptographic Provider
        3       Microsoft Base DSS Cryptographic Provider
        1       Microsoft Base Smart Card Crypto Provider
       18       Microsoft DH SChannel Cryptographic Provider
        1       Microsoft Enhanced Cryptographic Provider v1.0
       13       Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider
       24       Microsoft Enhanced RSA and AES Cryptographic Provider
       12       Microsoft RSA SChannel Cryptographic Provider
        1       Microsoft Strong Cryptographic Provider

Provider types and provider names have been listed.
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.
    DWORD       cbName;
    DWORD       dwType;
    DWORD       dwIndex;
    LPWSTR pszName = NULL;//这个有修改，类型定义的不对。

    // Print header lines for providers.
    printf("Listing Available Providers:\n");
    printf("Provider type\tProvider Name\n");
    printf("_____________\t_____________________________________\n");

    // Loop through enumerating providers.
    dwIndex = 0;
    while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        //  cbName returns the length of the name of the next provider. 
        //  Allocate memory in a buffer to retrieve that name.
        if (!(pszName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) {
            printf("ERROR - LocalAlloc failed\n");
            exit(1);
        }

        //  Get the provider name.
        if (CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) {
            printf("     %4.0d\t%ls\n", dwType, pszName);
        } else {
            printf("ERROR - CryptEnumProviders failed.\n");
            exit(1);
        }

        LocalFree(pszName);
    } // End of while loop

    printf("\nProvider types and provider names have been listed.\n");
}


EXTERN_C
__declspec(dllexport)
void WINAPI EnumProviderTypes()
/*
The following example shows a loop listing all available cryptographic service provider types.

https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumprovidertypesa
*/
/*
测试效果：
Listing Available Provider Types:
Provider type   Provider Type Name
_____________   _____________________________________
        1       RSA Full (Signature and Key Exchange)
        3       DSS Signature
       12       RSA SChannel
       13       DSS Signature with Diffie-Hellman Key Exchange
       18       Diffie-Hellman SChannel
       24       RSA Full and AES
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.
    DWORD       dwIndex;
    DWORD       dwType;
    DWORD       cbName;
    LPTSTR      pszName;

    //   Print header lines for provider types.
    printf("Listing Available Provider Types:\n");
    printf("Provider type\tProvider Type Name\n");
    printf("_____________\t_____________________________________\n");

    // Loop through enumerating provider types.
    dwIndex = 0;
    while (CryptEnumProviderTypes(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        //  cbName returns the length of the name of the next provider type.
        //  Allocate memory in a buffer to retrieve that name.
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) {
            printf("ERROR - LocalAlloc failed.\n");
            exit(1);
        }

        //  Get the provider type name.
        if (CryptEnumProviderTypes(dwIndex++, NULL, NULL, &dwType, pszName, &cbName)) {
            printf("     %4.0d\t%ls\n", dwType, pszName);
        } else {
            printf("ERROR - CryptEnumProviderTypes\n");
            exit(1);
        }

        LocalFree(pszName);
    } // End of while loop.
}


void MyHandleError(TCHAR * s)
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.
{
    _tprintf(TEXT("An error occurred in running the program.\n"));
    _tprintf(TEXT("%s\n"), s);
    _tprintf(TEXT("Error number %x\n."), GetLastError());
    _tprintf(TEXT("Program terminating.\n"));
    exit(1);
}


void Wait(const TCHAR * s)
{
    char x;
    _tprintf(s);
    x = getchar();
}


EXTERN_C
__declspec(dllexport)
void WINAPI EnumCsp(int argc, _TCHAR * argv[])
/*
Example C Program: Enumerating CSP Providers and Provider Types
05/31/2018
3 minutes to read

The following example lists the CSPs available on a computer and uses the following CryptoAPI functions:

CryptEnumProviderTypes
CryptEnumProviders
CryptGetDefaultProvider
CryptGetProvParam
This example uses the function MyHandleError. The code for this function is included in this example.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

The following example shows enumerating CSPs and provider types.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-enumerating-csp-providers-and-provider-types
*/
/*
测试效果：
Listing Available Provider Types.
Provider type    Provider Type Name
_____________    _____________________________________
        1        RSA Full (Signature and Key Exchange)
        3        DSS Signature
       12        RSA SChannel
       13        DSS Signature with Diffie-Hellman Key Exchange
       18        Diffie-Hellman SChannel
       24        RSA Full and AES


Listing Available Providers.
Provider type    Provider Name
_____________    _____________________________________
        1        Microsoft Base Cryptographic Provider v1.0
       13        Microsoft Base DSS and Diffie-Hellman Cryptographic Provider
        3        Microsoft Base DSS Cryptographic Provider
        1        Microsoft Base Smart Card Crypto Provider
       18        Microsoft DH SChannel Cryptographic Provider
        1        Microsoft Enhanced Cryptographic Provider v1.0
       13        Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider
       24        Microsoft Enhanced RSA and AES Cryptographic Provider
       12        Microsoft RSA SChannel Cryptographic Provider
        1        Microsoft Strong Cryptographic Provider

The default provider name is "Microsoft Strong Cryptographic Provider"

Enumerating the supported algorithms

     Algid      Bits      Type        Name         Algorithm
                                     Length          Name
    ________________________________________________________
    00006602h    128     Encrypt       4           RC2
    00006801h    128     Encrypt       4           RC4
    00006601h    56      Encrypt       4           DES
    00006609h    112     Encrypt       13          3DES TWO KEY
    00006603h    168     Encrypt       5           3DES
    00008004h    160     Hash          6           SHA-1
    00008001h    128     Hash          4           MD2
    00008002h    128     Hash          4           MD4
    00008003h    128     Hash          4           MD5
    00008008h    288     Hash          12          SSL3 SHAMD5
    00008005h    0       Hash          4           MAC
    00002400h    1024    Signature     9           RSA_SIGN
    0000a400h    1024    Exchange      9           RSA_KEYX
    00008009h    0       Hash          5           HMAC

Press Enter to continue.

The program completed without error.
*/
{
    // Declare and initialize variables.
    HCRYPTPROV hProv;
    LPTSTR pszName;
    DWORD dwType;
    DWORD cbName;
    DWORD dwIndex = 0;
    BYTE * ptr;
    ALG_ID aiAlgid;
    DWORD dwBits;
    DWORD dwNameLen;
    CHAR szName[100];
    BYTE pbData[1024];
    DWORD cbData = 1024;
    DWORD dwIncrement = sizeof(DWORD);
    DWORD dwFlags = CRYPT_FIRST;
    DWORD dwParam = PP_CLIENT_HWND;
    const CHAR * pszAlgType = NULL;
    BOOL fMore = TRUE;
    LPTSTR pbProvName;
    DWORD cbProvName;

    // Print header lines for provider types.
    _tprintf(TEXT("Listing Available Provider Types.\n"));
    _tprintf(TEXT("Provider type    Provider Type Name\n"));
    _tprintf(TEXT("_____________    ")
             TEXT("_____________________________________\n"));

    // Loop through enumerating provider types.
    dwIndex = 0;
    while (CryptEnumProviderTypes(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        // cbName is the length of the name of the next provider type.

        // Allocate memory in a buffer to retrieve that name.
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) {
            MyHandleError(TEXT("ERROR - LocalAlloc failed!"));
        }

        // Get the provider type name.
        if (CryptEnumProviderTypes(dwIndex++, NULL, NULL, &dwType, pszName, &cbName)) {
            _tprintf(TEXT("     %4.0d        %s\n"), dwType, pszName);
        } else {
            MyHandleError(TEXT("ERROR - CryptEnumProviders"));
        }

        LocalFree(pszName);
    }

    // Print header lines for providers.
    _tprintf(TEXT("\n\nListing Available Providers.\n"));
    _tprintf(TEXT("Provider type    Provider Name\n"));
    _tprintf(TEXT("_____________    ")
             TEXT("_____________________________________\n"));

    // Loop through enumerating providers.
    dwIndex = 0;
    while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        // cbName is the length of the name of the next provider.
        // Allocate memory in a buffer to retrieve that name.
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) {
            MyHandleError(TEXT("ERROR - LocalAlloc failed!"));
        }

        // Get the provider name.
        if (CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) {
            _tprintf(TEXT("     %4.0d        %s\n"), dwType, pszName);
        } else {
            MyHandleError(TEXT("ERROR - CryptEnumProviders"));
        }

        LocalFree(pszName);
    } // End while loop.

    // Get the name of the default CSP specified for the PROV_RSA_FULL type for the computer.

    // Get the length of the RSA_FULL default provider name.
    if (!(CryptGetDefaultProvider(
        PROV_RSA_FULL,
        NULL,
        CRYPT_MACHINE_DEFAULT,
        NULL,
        &cbProvName))) {
        MyHandleError(TEXT("Error getting the length of the ")
                      TEXT("default provider name."));
    }

    // Allocate local memory for the name of the default provider.
    if (!(pbProvName = (LPTSTR)LocalAlloc(
        LMEM_ZEROINIT,
        cbProvName))) {
        MyHandleError(TEXT("Error during memory allocation ")
                      TEXT("for provider name."));
    }

    // Get the name of the default PROV_RSA_FULL provider.
    if (CryptGetDefaultProvider(PROV_RSA_FULL, NULL, CRYPT_MACHINE_DEFAULT, pbProvName, &cbProvName)) {
        _tprintf(TEXT("\nThe default provider name is \"%s\"\n"), pbProvName);
    } else {
        MyHandleError(TEXT("Getting the provider name failed."));
    }

    LocalFree(pbProvName);

    //  Acquire a cryptographic context.
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL)) {
        MyHandleError(TEXT("Error during CryptAcquireContext!"));
    }

    // Enumerate the supported algorithms.

    // Print header for algorithm information table.
    _tprintf(TEXT("\nEnumerating the supported ")
             TEXT("algorithms\n\n"));
    _tprintf(TEXT("     Algid      Bits      Type        ")
             TEXT("Name         Algorithm\n"));
    _tprintf(TEXT("                                     Length")
             TEXT("          Name\n"));
    _tprintf(TEXT("    _______________________________________")
             TEXT("_________________\n"));

    while (fMore) {
        // Retrieve information about an algorithm.
        if (CryptGetProvParam(hProv, PP_ENUMALGS, pbData, &cbData, dwFlags)) {
            // Extract algorithm information from the pbData buffer.
            dwFlags = 0;
            ptr = pbData;
            aiAlgid = *(ALG_ID *)ptr;
            ptr += sizeof(ALG_ID);
            dwBits = *(DWORD *)ptr;
            ptr += dwIncrement;
            dwNameLen = *(DWORD *)ptr;
            ptr += dwIncrement;
            //strncpy_s(szName, (char *)ptr, sizeof(szName), dwNameLen);//这个把第二个和第三个参数写反了。
            strncpy_s(szName, sizeof(szName), (char *)ptr, dwNameLen);

            // Determine the algorithm type.
            switch (GET_ALG_CLASS(aiAlgid)) {
            case ALG_CLASS_DATA_ENCRYPT:
                pszAlgType = "Encrypt  ";
                break;
            case ALG_CLASS_HASH:
                pszAlgType = "Hash     ";
                break;
            case ALG_CLASS_KEY_EXCHANGE:
                pszAlgType = "Exchange ";
                break;
            case ALG_CLASS_SIGNATURE:
                pszAlgType = "Signature";
                break;
            default:
                pszAlgType = "Unknown  ";
                break;
            }

            // Print information about the algorithm.
            printf("    %8.8xh    %-4d    %s     %-2d          %s\n",
                   aiAlgid,
                   dwBits,
                   pszAlgType,
                   dwNameLen,
                   szName);
        } else {
            fMore = FALSE;
        }
    }

    //Wait(TEXT("\nPress Enter to continue."));

    if (!(CryptReleaseContext(hProv, 0))) {
        MyHandleError(TEXT("Error during CryptReleaseContext."));
    }

    if (GetLastError() == ERROR_NO_MORE_ITEMS) {
        _tprintf(TEXT("\nThe program completed without error.\n"));
    } else {
        MyHandleError(TEXT("Error reading algorithm!"));
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
HRESULT WINAPI EnumProviders(void)
/*
Enumerating Installed Providers
01/08/2021
2 minutes to read

Enumerate the cryptographic providers installed on the computer.
This sample enumerates the Cryptography API (CryptoAPI) and
Cryptography API: Next Generation (CNG) providers.

The following example shows how to use the Certificate Enrollment API to enumerate the providers installed on a computer.

https://docs.microsoft.com/en-us/windows/win32/seccertenroll/enumerating-installed-providers
*/
{
    CComPtr<ICspInformations>     pCSPs;   // Provider collection
    CComPtr<ICspInformation>      pCSP;    // Provider instgance
    HRESULT           hr = S_OK;  // Return value
    long              lCount = 0;     // Count of providers
    CComBSTR          bstrName;            // Provider name
    VARIANT_BOOL      bLegacy;             // CryptoAPI or CNG

    // Create a collection of cryptographic providers.
    hr = CoCreateInstance(
        __uuidof(CCspInformations),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(ICspInformations),
        (void **)&pCSPs);
    if (FAILED(hr)) return hr;

    // Add the providers installed on the computer.
    hr = pCSPs->AddAvailableCsps();
    if (FAILED(hr)) return hr;

    // Retrieve the number of installed providers.
    hr = pCSPs->get_Count(&lCount);
    if (FAILED(hr)) return hr;

    // Print the providers to the console.
    // Print the name and a value that specifies whether the CSP is a legacy or CNG provider.
    for (long i = 0; i < lCount; i++) {
        hr = pCSPs->get_ItemByIndex(i, &pCSP);
        if (FAILED(hr)) return hr;

        hr = pCSP->get_Name(&bstrName);
        if (FAILED(hr)) return hr;

        hr = pCSP->get_LegacyCsp(&bLegacy);
        if (FAILED(hr)) return hr;

        if (VARIANT_TRUE == bLegacy)
            wprintf_s(L"%2d. Legacy: ", i);
        else
            wprintf_s(L"%2d. CNG: ", i);

        wprintf_s(L"%s\n", static_cast<wchar_t *>(bstrName.m_str));

        pCSP = NULL;
    }

    //printf_s("\n\nHit any key to continue: ");
    //(void)_getch();

    return hr;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL GetExportedKey(HCRYPTKEY hKey, DWORD dwBlobType, LPBYTE * ppbKeyBlob, LPDWORD pdwBlobLen)
/*
The following example shows how to export a cryptographic key or a key pair in a more secure manner. 
This example assumes that a cryptographic context has been acquired and that a public key is available for export. 
For an example that includes the complete context for using this function, 
see Example C Program: Signing a Hash and Verifying the Hash Signature. 
For another example that uses this function, see Example C Program: Exporting a Session Key.

https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey
*/
{
    DWORD dwBlobLength;
    *ppbKeyBlob = NULL;
    *pdwBlobLen = 0;

    // Export the public key. Here the public key is exported to a PUBLICKEYBLOB. 
    // This BLOB can be written to a file and sent to another user.
    if (CryptExportKey(hKey, NULL, dwBlobType, 0, NULL, &dwBlobLength)) {
        printf("Size of the BLOB for the public key determined. \n");
    } else {
        printf("Error computing BLOB length.\n");
        return FALSE;
    }

    // Allocate memory for the pbKeyBlob.
    if (*ppbKeyBlob = (LPBYTE)malloc(dwBlobLength)) {
        printf("Memory has been allocated for the BLOB. \n");
    } else {
        printf("Out of memory. \n");
        return FALSE;
    }

    // Do the actual exporting into the key BLOB.
    if (CryptExportKey(hKey, NULL, dwBlobType, 0, *ppbKeyBlob, &dwBlobLength)) {
        printf("Contents have been written to the BLOB. \n");
        *pdwBlobLen = dwBlobLength;
    } else {
        printf("Error exporting key.\n");
        free(*ppbKeyBlob);
        *ppbKeyBlob = NULL;
        return FALSE;
    }

    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// This example program creates a session key and a simple key BLOB holding that session key. 
// The key BLOB can be written to disk and later read from a disk file.


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


void MyHandleError(char * s)
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.
{
    printf("An error occurred in running the program.\n");
    printf("%s\n", s);
    printf("Error number %x\n.", GetLastError());
    printf("Program terminating.\n");
    exit(1);
}


EXTERN_C
__declspec(dllexport)
void WINAPI ExportSessionKey(void)
/*
Example C Program: Exporting a Session Key

01/08/2021
3 minutes to read

The following example creates a random session key and creates an exportable key BLOB. 
The example illustrates the use of CryptGetUserKey, CryptExportKey, and related functions.

This example illustrates the following tasks and CryptoAPI functions:

Acquiring a CSP context using CryptAcquireContext.
Gaining access to two different pairs of public/private keys using CryptGetUserKey.
Generating an exportable session key using CryptGenKey.
Creating a simple key BLOB containing a session key using CryptExportKey.
Destroying a session key and access to the two pairs of public/private keys using CryptDestroyKey.
Releasing the CSP context using CryptReleaseContext.
This example uses the function MyHandleError. 
The code for this function is included with the sample. 
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-exporting-a-session-key
*/
{
    // Declare and initialize variables.
    HCRYPTPROV hProv;       // CSP handle
    HCRYPTKEY hSignKey;     // Signature key pair handle
    HCRYPTKEY hXchgKey;     // Exchange key pair handle
    HCRYPTKEY hKey;         // Session key handle
    BYTE * pbKeyBlob;        // Pointer to a simple key BLOB
    DWORD dwBlobLen;        // The length of the key BLOB

    // Acquire a cryptographic provider context handle.
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("The CSP has been acquired. \n");
    } else {
        MyHandleError("Error during CryptAcquireContext.");
    }

    // Get a handle to the signature key.
    // The signature key must exist before it can be retrieved.
    // For more information, see the CryptGetUserKey documentation.
    if (CryptGetUserKey(hProv, AT_SIGNATURE, &hSignKey)) {
        printf("The signature key has been acquired. \n");
    } else {
        MyHandleError("Error during CryptGetUserKey for signkey.");
    }

    // Get a handle to the key exchange key.
    // The key must exist before it can be retrieved.
    // For more information, see the CryptGetUserKey documentation.

    if (CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hXchgKey)) {
        printf("The key exchange key has been acquired. \n");
    } else {
        printf("Error during CryptGetUserKey exchange key.");
    }
    // hSignKey may be used to verify a signature. hXchgKey will be used to export a session key.

    // Generate a session key.
    if (CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE, &hKey)) {
        printf("Original session key is created. \n");
    } else {
        MyHandleError("ERROR -- CryptGenKey.");
    }

    // Determine the size of the key BLOB and allocate memory.
    if (CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, NULL, &dwBlobLen)) {
        printf("Size of the BLOB for the session key determined. \n");
    } else {
        MyHandleError("Error computing BLOB length.");
    }

    if (pbKeyBlob = (BYTE *)malloc(dwBlobLen)) {
        printf("Memory has been allocated for the BLOB. \n");
    } else {
        MyHandleError("Out of memory. \n");
    }

    // Export the key into a simple key BLOB.
    if (CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, pbKeyBlob, &dwBlobLen)) {
        printf("Contents have been written to the BLOB. \n");
    } else {
        MyHandleError("Error during CryptExportKey.");
    }

    //   At this point, other processing such as writing the key BLOB to a file could be done.

    // After all processing, clean up.

    //  Free the memory used by the key BLOB.
    free(pbKeyBlob);

    // Destroy the session key.
    if (hKey)
        CryptDestroyKey(hKey);

    // Destroy the signature key handle.
    if (hSignKey)
        CryptDestroyKey(hSignKey);

    // Destroy the key exchange key handle.
    if (hXchgKey)
        CryptDestroyKey(hXchgKey);

    // Release the provider handle.
    if (hProv)
        CryptReleaseContext(hProv, 0);
    printf("The program ran to completion without error. \n");
}// End of main                                                    


//////////////////////////////////////////////////////////////////////////////////////////////////


// DesKeyBlob:      A plaintext key BLOB stored in a byte array. 
//                  The byte array  must have the following format:
//                      BLOBHEADER hdr;
//                      DWORD dwKeySize;
//                      BYTE rgbKeyData [];
BYTE DesKeyBlob[] = {
    0x08,0x02,0x00,0x00,0x01,0x66,0x00,0x00, // BLOB header 
    0x08,0x00,0x00,0x00,                     // key length, in bytes
    0xf1,0x0e,0x25,0x7c,0x6b,0xce,0x0d,0x34  // DES key with parity
};


EXTERN_C
__declspec(dllexport)
int WINAPI ImportPlaintextKey()
/*
Example C Program: Importing a Plaintext Key
01/08/2021
2 minutes to read

Many of the functions in this SDK require that you identify a key by using an HCRYPTKEY handle. 
If your key is contained in a byte array, 
you can create a handle by using the CryptImportKey function as shown in the following example.

This example demonstrates the following tasks and CryptoAPI functions:

Acquiring a handle to a cryptographic service provider by calling CryptAcquireContext.
Importing a plaintext key into the CSP key container by calling CryptImportKey.
Exporting a key from the key container by calling CyptExportKey.
Printing the exported key to the console to verify that the plaintext key was indeed imported into the container.
Releasing the memory reserved for the plaintext key.
Releasing the CSP by calling CryptReleaseContext.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--importing-a-plaintext-key
*/
{
    // Declare variables.
    // hProv:           Cryptographic service provider (CSP).
    //                  This example uses the Microsoft Enhanced Cryptographic Provider.
    // hKey:            Key to be used. In this example, you import the key as a PLAINTEXTKEYBLOB.
    // dwBlobLen:       Length of the plaintext key.
    // pbKeyBlob:       Pointer to the exported key.

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    DWORD dwBlobLen;
    BYTE * pbKeyBlob;

    // Acquire a handle to the CSP.
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        // If the key container cannot be opened, try creating a new
        // container by specifying a container name and setting the CRYPT_NEWKEYSET flag.
        if (NTE_BAD_KEYSET == GetLastError()) {
            if (!CryptAcquireContext(
                &hProv,
                L"mytestcontainer",
                MS_ENHANCED_PROV,
                PROV_RSA_FULL,
                CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT)) {
                printf("Error in AcquireContext 0x%08x \n", GetLastError());
                return 1;
            }
        } else {
            printf(" Error in AcquireContext 0x%08x \n", GetLastError());
            return 1;
        }
    }

    // Use the CryptImportKey function to import the PLAINTEXTKEYBLOB
    // BYTE array into the key container. The function returns a 
    // pointer to an HCRYPTKEY variable that contains the handle of the imported key.
    if (!CryptImportKey(hProv, DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey)) {
        printf("Error 0x%08x in importing the Des key \n", GetLastError());
    }

    // For the purpose of this example, you can export the key and 
    // print it to verify that the plain text key created above is  
    // the key that was imported into the CSP.
    // Call CryptExportKey once to determine the length of the key.
    // Allocate memory for the BLOB, and call CryptExportKey again
    // to retrieve the key from the CSP key container.

    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLen)) {
        printf("Error 0x%08x computing BLOB length.\n", GetLastError());
        return 1;
    }

    if (pbKeyBlob = (BYTE *)malloc(dwBlobLen)) {
        printf("Memory has been allocated for the BLOB. \n");
    } else {
        printf("Out of memory. \n");
        return 1;
    }

    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
        printf("Error 0x%08x exporting key.\n", GetLastError());
        return 1;
    }

    DWORD count = 0;
    printf("Printing Key BLOB for verification \n");
    for (count = 0; count < dwBlobLen;) {
        printf("%02x", pbKeyBlob[count]);
        count++;
    }

    // Free resources.

    if (pbKeyBlob) {
        free(pbKeyBlob);
    }

    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.


//void MyHandleError(LPTSTR psz)
//// This example uses the function MyHandleError, a simple error
//// handling function to print an error message and exit 
//// the program. 
//// For most applications, replace this function with one 
//// that does more extensive error reporting.
//{
//    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
//    _ftprintf(stderr, TEXT("%s\n"), psz);
//    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
//    _ftprintf(stderr, TEXT("Program terminating. \n"));
//    exit(1);
//} // End of MyHandleError.


EXTERN_C
__declspec(dllexport)
void WINAPI CreatingKeyContainerGeneratingKeys(void)
/*
Example C Program: Creating a Key Container and Generating Keys
01/08/2021
3 minutes to read

The following example creates a named key container and adds a signature key pair and 
an exchange key pair to the container. 
This example can be run without problem even if the named key container and 
cryptographic keys already exist.

 Note
An application should not use the default key container to store private keys. 
When multiple applications use the same container, 
one application may change or destroy the keys that another application needs to have available. 
It is recommended that applications use key containers that are linked to the application. 
Doing so reduces the risk of other applications tampering with keys that are necessary for an application to function properly.

This example demonstrates the following tasks and CryptoAPI functions:

It attempts to acquire the named key container. 
If the named key container does not already exist, it is created.
If a signature key pair does not exist in the key container, 
it creates a signature key pair within the key container.
If an exchange key pair does not exist in the key container, 
it creates an exchange key pair within the key container.
These operations only need to be performed once for each user on each computer. 
If the named key container and key pairs have already been created, this sample performs no operations.

This example uses the following CryptoAPI functions:
CryptAcquireContext
CryptDestroyKey
CryptGenKey
CryptGetUserKey
CryptReleaseContext

This example uses the function MyHandleError. 
The code for this function is included with the sample. 
Code for this and other auxiliary functions is also listed under General Purpose Functions.
*/
{
    // Handle for the cryptographic provider context.
    HCRYPTPROV hCryptProv;

    // The name of the container.
    LPCTSTR pszContainerName = TEXT("My Sample Key Container");

    // Begin processing. Attempt to acquire a context by using the 
    // specified key container.
    if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, 0)) {
        _tprintf(TEXT("A crypto context with the %s key container ")
                 TEXT("has been acquired.\n"),
                 pszContainerName);
    } else {
        // Some sort of error occurred in acquiring the context. 
        // This is most likely due to the specified container 
        // not existing. Create a new key container.
        if (GetLastError() == NTE_BAD_KEYSET) {
            if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                _tprintf(TEXT("A new key container has been ")
                         TEXT("created.\n"));
            } else {
                MyHandleError(TEXT("Could not create a new key ")
                              TEXT("container.\n"));
            }
        } else {
            MyHandleError(TEXT("CryptAcquireContext failed.\n"));
        }
    }

    // A context with a key container is available.
    // Attempt to get the handle to the signature key. 

    // Public/private key handle.
    HCRYPTKEY hKey;

    if (CryptGetUserKey(hCryptProv, AT_SIGNATURE, &hKey)) {
        _tprintf(TEXT("A signature key is available.\n"));
    } else {
        _tprintf(TEXT("No signature key is available.\n"));
        if (GetLastError() == NTE_NO_KEY) {
            // The error was that there is a container but no key.

            // Create a signature key pair. 
            _tprintf(TEXT("The signature key does not exist.\n"));
            _tprintf(TEXT("Create a signature key pair.\n"));
            if (CryptGenKey(hCryptProv, AT_SIGNATURE, 0, &hKey)) {
                _tprintf(TEXT("Created a signature key pair.\n"));
            } else {
                MyHandleError(TEXT("Error occurred creating a ")
                              TEXT("signature key.\n"));
            }
        } else {
            MyHandleError(TEXT("An error other than NTE_NO_KEY ")
                          TEXT("getting a signature key.\n"));
        }
    } // End if.

    _tprintf(TEXT("A signature key pair existed, or one was ")
             TEXT("created.\n\n"));

    // Destroy the signature key.
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            MyHandleError(TEXT("Error during CryptDestroyKey."));
        }

        hKey = NULL;
    }

    // Next, check the exchange key. 
    if (CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hKey)) {
        _tprintf(TEXT("An exchange key exists.\n"));
    } else {
        _tprintf(TEXT("No exchange key is available.\n"));

        // Check to determine whether an exchange key needs to be created.
        if (GetLastError() == NTE_NO_KEY) {
            // Create a key exchange key pair.
            _tprintf(TEXT("The exchange key does not exist.\n"));
            _tprintf(TEXT("Attempting to create an exchange key ")
                     TEXT("pair.\n"));
            if (CryptGenKey(hCryptProv, AT_KEYEXCHANGE, 0, &hKey)) {
                _tprintf(TEXT("Exchange key pair created.\n"));
            } else {
                MyHandleError(TEXT("Error occurred attempting to ")
                              TEXT("create an exchange key.\n"));
            }
        } else {
            MyHandleError(TEXT("An error other than NTE_NO_KEY ")
                          TEXT("occurred.\n"));
        }
    }

    // Destroy the exchange key.
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            MyHandleError(TEXT("Error during CryptDestroyKey."));
        }

        hKey = NULL;
    }

    // Release the CSP.
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0))) {
            MyHandleError(TEXT("Error during CryptReleaseContext."));
        }
    }

    _tprintf(TEXT("Everything is okay. A signature key "));
    _tprintf(TEXT("pair and an exchange key exist in "));
    _tprintf(TEXT("the %s key container.\n"), pszContainerName);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//  Copyright (C) Microsoft.  All rights reserved.
//  Example code using CryptAcquireContext.


//void MyHandleError(LPTSTR psz)
//// This example uses the function MyHandleError, a simple error
//// handling function to print an error message and exit the program. 
//// For most applications, replace this function with one 
//// that does more extensive error reporting.
//{
//    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
//    _ftprintf(stderr, TEXT("%s\n"), psz);
//    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
//    _ftprintf(stderr, TEXT("Program terminating. \n"));
//    exit(1);
//} // End of MyHandleError.


EXTERN_C
__declspec(dllexport)
void WINAPI AcquireCryptContext(void)
/*
Example C Program: Using CryptAcquireContext
01/08/2021
3 minutes to read

The following example demonstrates several different ways to use the CryptAcquireContext and 
related CryptoAPI functions to work with a cryptographic service provider (CSP) and a key container.

This example demonstrates the following tasks and CryptoAPI functions:

Use the CryptAcquireContext function to acquire a handle for the default CSP and the default key container. 
If no default key container exists, use the CryptAcquireContext function to create the default key container.
Use the CryptGetProvParam function to retrieve information about a CSP and a key container.
Increase the reference count on the provider by using the CryptContextAddRef function.
Release a CSP by using the CryptReleaseContext function.
Create a named key container by using the CryptAcquireContext function.
Acquire a handle for a CSP by using the newly created key container.
Delete a key container by using the CryptAcquireContext function.
This example uses the function MyHandleError. 
The code for this function is included with the sample. 
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptacquirecontext
*/
{
    // Declare and initialize variables.
    HCRYPTPROV hCryptProv;

    // Get a handle to the default PROV_RSA_FULL provider.
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        _tprintf(TEXT("CryptAcquireContext succeeded.\n"));
    } else {
        if (GetLastError() == NTE_BAD_KEYSET) {
            // No default container was found. Attempt to create it.
            if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                _tprintf(TEXT("CryptAcquireContext succeeded.\n"));
            } else {
                MyHandleError(TEXT("Could not create the default ")
                              TEXT("key container.\n"));
            }
        } else {
            MyHandleError(TEXT("A general error running ")
                          TEXT("CryptAcquireContext."));
        }
    }

    CHAR pszName[1000];
    DWORD cbName;

    // Read the name of the CSP.
    cbName = 1000;
    if (CryptGetProvParam(hCryptProv, PP_NAME, (BYTE *)pszName, &cbName, 0)) {
        _tprintf(TEXT("CryptGetProvParam succeeded.\n"));
        printf("Provider name: %s\n", pszName);
    } else {
        MyHandleError(TEXT("Error reading CSP name.\n"));
    }

    // Read the name of the key container.
    cbName = 1000;
    if (CryptGetProvParam(hCryptProv, PP_CONTAINER, (BYTE *)pszName, &cbName, 0)) {
        _tprintf(TEXT("CryptGetProvParam succeeded.\n"));
        printf("Key Container name: %s\n", pszName);
    } else {
        MyHandleError(TEXT("Error reading key container name.\n"));
    }

    // Perform cryptographic operations.
    //...

    //  Add to the reference count on the provider. When the 
    //  reference count on a provider is greater than one,  
    //  CryptReleaseContext reduces the reference count but does not free the provider.

    if (CryptContextAddRef(hCryptProv, NULL, 0)) {
        _tprintf(TEXT("CryptcontextAddRef succeeded.\n"));
    } else {
        MyHandleError(TEXT("Error during CryptContextAddRef!\n"));
    }

    //  The reference count on hCryptProv is now greater than one. 
    //  The first call to CryptReleaseContext will not release the provider handle. 

    //  Release the context once.
    if (CryptReleaseContext(hCryptProv, 0)) {
        _tprintf(TEXT("The first call to CryptReleaseContext ")
                 TEXT("succeeded.\n"));
    } else {
        MyHandleError(TEXT("Error during ")
                      TEXT("CryptReleaseContext #1!\n"));
    }

    // Release the provider handle again.
    if (CryptReleaseContext(hCryptProv, 0)) {
        _tprintf(TEXT("The second call to CryptReleaseContext ")
                 TEXT("succeeded.\n"));
    } else {
        MyHandleError(TEXT("Error during ")
                      TEXT("CryptReleaseContext #2!\n"));
    }

    // Get a handle to a PROV_RSA_FULL provider and
    // create a key container named "My Sample Key Container".
    LPCTSTR pszContainerName = TEXT("My Sample Key Container");

    hCryptProv = NULL;
    if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        _tprintf(TEXT("CryptAcquireContext succeeded. \n"));
        _tprintf(TEXT("New key set created. \n"));

        // Release the provider handle and the key container.
        if (hCryptProv) {
            if (CryptReleaseContext(hCryptProv, 0)) {
                hCryptProv = NULL;
                _tprintf(TEXT("CryptReleaseContext succeeded. \n"));
            } else {
                MyHandleError(TEXT("Error during ")
                              TEXT("CryptReleaseContext!\n"));
            }
        }
    } else {
        if (GetLastError() == NTE_EXISTS) {
            _tprintf(TEXT("The named key container could not be ")
                     TEXT("created because it already exists.\n"));

            // Just continue the program. The named container will be reopened below.
        } else {
            MyHandleError(TEXT("Error during CryptAcquireContext ")
                          TEXT("for a new key container."));
        }
    }

    // Get a handle to the provider by using the new key container. 
    // Note: This key container will be empty until keys
    // are explicitly created by using the CryptGenKey function.
    if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, 0)) {
        _tprintf(TEXT("Acquired the key set just created. \n"));
    } else {
        MyHandleError(TEXT("Error during CryptAcquireContext!\n"));
    }

    // Perform cryptographic operations.

    // Release the provider handle.
    if (CryptReleaseContext(hCryptProv, 0)) {
        _tprintf(TEXT("CryptReleaseContext succeeded. \n"));
    } else {
        MyHandleError(TEXT("Error during CryptReleaseContext!\n"));
    }

    // Delete the new key container.
    if (CryptAcquireContext(&hCryptProv, pszContainerName, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET)) {
        _tprintf(TEXT("Deleted the key container just created. \n"));
    } else {
        MyHandleError(TEXT("Error during CryptAcquireContext!\n"));
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define PASSWORD_LENGTH 512


//void MyHandleError(char * s)
//// This example uses the function MyHandleError, a simple error
//// handling function to print an error message and exit
//// the program.
//// For most applications, replace this function with one
//// that does more extensive error reporting.
//{
//    printf("An error occurred in running the program.\n");
//    printf("%s\n", s);
//    printf("Error number %x\n.", GetLastError());
//    printf("Program terminating.\n");
//    exit(1);
//}


void GetConsoleInput(char * strInput, UINT  intMaxChars)
// The GetConsoleInput function gets an array of characters from the
// keyboard, while printing only asterisks to the screen.
{
    char ch;
    char minChar = ' ';
    minChar++;

    ch = (char)_getch();
    while (ch != '\r') {
        if (ch == '\b' && strlen(strInput) > 0) {
            strInput[strlen(strInput) - 1] = '\0';
            printf("\b \b");
        } else if ((ch >= minChar) && (strlen(strInput) < intMaxChars)) {
            strInput[strlen(strInput) + 1] = '\0';
            strInput[strlen(strInput)] = ch;
            _putch('*');
        }
        ch = (char)_getch();
    }
    _putch('\n');
}


EXTERN_C
__declspec(dllexport)
void WINAPI DerivingSessionKeyFromPassword()
/*
Example C Program: Deriving a Session Key from a Password
01/08/2021
2 minutes to read

The following example demonstrates creating a session cryptographic key from the hash of a password as well as the use of the function CryptDeriveKey and related functions.

This example illustrates the following tasks and CryptoAPI functions:

Calling CryptAcquireContext to acquiring a handle for the default CSP and the default key container.
Using CryptCreateHash to create an empty hash object.
Hashing the text of a password using CryptHashData.
Deriving a session key from the hashed password using CryptDeriveKey.
Destroying the hash and the password.
Using CryptReleaseContext to release the CSP.
This example uses the function MyHandleError. Code for this function is included with the sample.

Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-deriving-a-session-key-from-a-password
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.

    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    CHAR szPassword[PASSWORD_LENGTH] = "";
    DWORD dwLength;

    // Get the password from the user.
    fprintf(stderr, "Enter a password to be used to create a key:");

    // Get a password while printing only asterisks to the screen.
    GetConsoleInput(szPassword, PASSWORD_LENGTH);
    printf("The password has been stored.\n");
    dwLength = (DWORD)strlen(szPassword);

    // Acquire a cryptographic provider context handle.
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("A context has been acquired. \n");
    } else {
        MyHandleError("Error during CryptAcquireContext!");
    }

    // Create an empty hash object.
    if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        printf("An empty hash object has been created. \n");
    } else {
        MyHandleError("Error during CryptCreateHash!");
    }

    // Hash the password string.
    if (CryptHashData(hHash, (BYTE *)szPassword, dwLength, 0)) {
        printf("The password has been hashed. \n");
    } else {
        MyHandleError("Error during CryptHashData!");
    }

    // Create a session key based on the hash of the password.
    if (CryptDeriveKey(hCryptProv, CALG_RC2, hHash, CRYPT_EXPORTABLE, &hKey)) {
        printf("The key has been derived. \n");
    } else {
        MyHandleError("Error during CryptDeriveKey!");
    }

    // Use hKey as appropriate to encrypt or decrypt a message.

    // Clean up.

    // Destroy the hash object.
    if (hHash) {
        if (!(CryptDestroyHash(hHash)))
            MyHandleError("Error during CryptDestroyHash");
    }

    // Destroy the session key.
    if (hKey) {
        if (!(CryptDestroyKey(hKey)))
            MyHandleError("Error during CryptDestroyKey");
    }

    // Release the provider handle.
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0)))
            MyHandleError("Error during CryptReleaseContext");
    }
    printf("The program to derive a key completed without error. \n");
} 


//////////////////////////////////////////////////////////////////////////////////////////////////


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


// Copyright (C) Microsoft.  All rights reserved.


EXTERN_C
__declspec(dllexport)
void WINAPI DuplicatingSessionKey()
/*
Example C Program: Duplicating a Session Key
01/08/2021
2 minutes to read

The following example creates a random session key, duplicates the key, 
sets some additional parameters on the original key, 
and destroys both the original and the duplicate keys. 
This example illustrates the use of CryptDuplicateKey and related functions.

This example illustrates the following tasks and CryptoAPI functions:

Accessing a cryptographic service provider (CSP) using CryptAcquireContext.
Creating a session key using CryptGenKey.
Duplicating the key created using CryptDuplicateKey.
Using CryptSetKeyParam to alter the key generation process in two different ways.
Filling a buffer with random bytes using CryptGenRandom.
Destroying the keys using CryptDestroyKey.
Releasing the CSP with CryptReleaseContext.
This example uses the function MyHandleError. 
The code for this function is included with the sample. 
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-duplicating-a-session-key
*/
{
    // Declare and initialize variables.
    HCRYPTPROV   hCryptProv;
    HCRYPTKEY    hOriginalKey;
    HCRYPTKEY    hDuplicateKey;
    DWORD        dwMode;
    BYTE         pbData[16];

    // Begin processing.
    printf("This program creates a session key and duplicates \n");
    printf("that key. Next, parameters are added to the original \n");
    printf("key. Finally, both keys are destroyed. \n\n");

    // Acquire a cryptographic provider context handle.
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("CryptAcquireContext succeeded. \n");
    } else {
        MyHandleError("Error during CryptAcquireContext!\n");
    }

    // Generate a key.
    if (CryptGenKey(hCryptProv, CALG_RC4, 0, &hOriginalKey)) {
        printf("Original session key is created. \n");
    } else {
        MyHandleError("ERROR - CryptGenKey.");
    }

    // Duplicate the key.
    if (CryptDuplicateKey(hOriginalKey, NULL, 0, &hDuplicateKey)) {
        printf("The session key has been duplicated. \n");
    } else {
        MyHandleError("ERROR - CryptDuplicateKey");
    }

    // Set additional parameters on the original key.
    // First, set the cipher mode.

    dwMode = CRYPT_MODE_ECB;
    if (CryptSetKeyParam(hOriginalKey, KP_MODE, (BYTE *)&dwMode, 0)) {
        printf("Key Parameters set. \n");
    } else {
        MyHandleError("Error during CryptSetKeyParam.");
    }

    // Generate a random initialization vector.
    if (CryptGenRandom(hCryptProv, 8, pbData)) {
        printf("Random sequence generated. \n");
    } else {
        MyHandleError("Error during CryptGenRandom.");
    }

    // Set the initialization vector.
    if (CryptSetKeyParam(hOriginalKey, KP_IV, pbData, 0)) {
        printf("Parameter set with random sequence as initialization vector. \n");
    } else {
        MyHandleError("Error during CryptSetKeyParam.");
    }

    // Clean up.

    if (hOriginalKey)
        if (!CryptDestroyKey(hOriginalKey))
            MyHandleError("Failed CryptDestroyKey\n");

    if (hDuplicateKey)
        if (!CryptDestroyKey(hDuplicateKey))
            MyHandleError("Failed CryptDestroyKey\n");

    if (hCryptProv)
        if (!CryptReleaseContext(hCryptProv, 0))
            MyHandleError("Failed CryptReleaseContext\n");

    printf("\nThe program ran to completion without error. \n");
}


//void MyHandleError(char * s)
////  This example uses the function MyHandleError, a simple error
////  handling function, to print an error message and exit 
////  the program. 
////  For most applications, replace this function with one 
////  that does more extensive error reporting.
//{
//    printf("An error occurred in running the program.\n");
//    printf("%s\n", s);
//    printf("Error number %x\n.", GetLastError());
//    printf("Program terminating.\n");
//    exit(1);
//}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.


EXTERN_C
__declspec(dllexport)
void WINAPI SessionKeyParameters()
/*
Example C Program: Setting and Getting Session Key Parameters
01/08/2021
2 minutes to read

The following example creates a random session key, gets and prints some default parameters of that key, 
sets a new parameters on the original key, then gets and prints the value of that new parameter. 
It cleans up by destroying the session key and releasing the cryptographic context.

This example illustrates the use of the following tasks and functions:

Accessing a CSP using CryptAcquireContext.
Filing a buffer with random bytes using CryptGenRandom.
Creating a session key using CryptGenKey.
Getting the value of key parameters using CryptGetKeyParam.
Using CryptSetKeyParam to alter the key generation process.
Destroying the keys using CryptDestroyKey.
Releasing the CSP with CryptReleaseContext.
This example uses the function MyHandleError. The code for this function is included with the sample. 
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-setting-and-getting-session-key-parameters
*/
{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    DWORD dwMode;
    BYTE pbData[16];
    BYTE pbRandomData[8];
    DWORD dwCount;
    DWORD i;

    // Acquire a cryptographic provider context handle.
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        MyHandleError(TEXT("Error during CryptAcquireContext."));
    }

    //  Generate eight bytes of random data into pbRandomData.
    if (CryptGenRandom(hProv, 8, pbRandomData)) {
        _tprintf(TEXT("Eight bytes of random data have been generated.\n"));
    } else {
        MyHandleError(TEXT("Random bytes were not correctly generated."));
    }

    // Create a random block cipher session key.
    if (!CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE, &hKey)) {
        MyHandleError(TEXT("Error during CryptGenKey."));
    }

    // Read the cipher mode.
    dwCount = sizeof(DWORD);
    if (CryptGetKeyParam(hKey, KP_MODE, (PBYTE)&dwMode, &dwCount, 0)) {
        // Print the cipher mode.
        _tprintf(TEXT("Default cipher mode: %d\n"), dwMode);
    } else {
        MyHandleError(TEXT("Error during CryptGetKeyParam."));
    }

    // Read the initialization vector.

    //  Get the length of the initialization vector.
    if (!CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0)) {
        MyHandleError(TEXT("Error getting the IV length"));
    }

    // Get the initialization vector, itself.
    if (CryptGetKeyParam(hKey, KP_IV, pbData, &dwCount, 0)) {
        // Print the initialization vector.
        _tprintf(TEXT("Default IV:"));
        for (i = 0; i < dwCount; i++) {
            _tprintf(TEXT("%2.2x "), pbData[i]);
        }

        _tprintf(TEXT("\n"));
    } else {
        MyHandleError(TEXT("Error getting the IV."));
    }

    //  Reset the initialization vector.
    if (CryptSetKeyParam(hKey, KP_IV, pbRandomData, 0)) {
        _tprintf(TEXT("New initialization vector is set.\n"));
    } else {
        MyHandleError(TEXT("The new IV was not set."));
    }

    // Read the new initialization vector.

    //  Get the length of the new initialization vector.
    if (!CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0)) {
        MyHandleError(TEXT("Error getting the IV length"));
    }

    // Get the initialization vector, itself.
    if (CryptGetKeyParam(hKey, KP_IV, pbData, &dwCount, 0)) {
        // Print the initialization vector.
        _tprintf(TEXT("RE-set IV:"));
        for (i = 0; i < dwCount; i++) {
            _tprintf(TEXT("%2.2x "), pbData[i]);
        }

        _tprintf(TEXT("\n"));
    } else {
        MyHandleError(TEXT("Error getting the IV."));
    }

    //  Clean up.

    //  Destroy the session key.
    if (hKey) {
        CryptDestroyKey(hKey);
    }

    // Release the provider handle.
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }
} 


//void MyHandleError(PTSTR psz)
////    This example uses the function MyHandleError, a simple error
////    handling function, to print an error message to the standard  
////    error (stderr) file and exit the program. 
////    For most applications, replace this function with one 
////    that does more extensive error reporting.
//{
//    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
//    _ftprintf(stderr, TEXT("%s\n"), psz);
//    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
//    _ftprintf(stderr, TEXT("Program terminating. \n"));
//    exit(1);
//} // End of MyHandleError.


//////////////////////////////////////////////////////////////////////////////////////////////////


// The key size, in bits.
#define DHKEYSIZE 512

// Prime in little-endian format.
static const BYTE g_rgbPrime[] =
{
    0x91, 0x02, 0xc8, 0x31, 0xee, 0x36, 0x07, 0xec,
    0xc2, 0x24, 0x37, 0xf8, 0xfb, 0x3d, 0x69, 0x49,
    0xac, 0x7a, 0xab, 0x32, 0xac, 0xad, 0xe9, 0xc2,
    0xaf, 0x0e, 0x21, 0xb7, 0xc5, 0x2f, 0x76, 0xd0,
    0xe5, 0x82, 0x78, 0x0d, 0x4f, 0x32, 0xb8, 0xcb,
    0xf7, 0x0c, 0x8d, 0xfb, 0x3a, 0xd8, 0xc0, 0xea,
    0xcb, 0x69, 0x68, 0xb0, 0x9b, 0x75, 0x25, 0x3d,
    0xaa, 0x76, 0x22, 0x49, 0x94, 0xa4, 0xf2, 0x8d
};

// Generator in little-endian format.
static BYTE g_rgbGenerator[] =
{
    0x02, 0x88, 0xd7, 0xe6, 0x53, 0xaf, 0x72, 0xc5,
    0x8c, 0x08, 0x4b, 0x46, 0x6f, 0x9f, 0x2e, 0xc4,
    0x9c, 0x5c, 0x92, 0x21, 0x95, 0xb7, 0xe5, 0x58,
    0xbf, 0xba, 0x24, 0xfa, 0xe5, 0x9d, 0xcb, 0x71,
    0x2e, 0x2c, 0xce, 0x99, 0xf3, 0x10, 0xff, 0x3b,
    0xcb, 0xef, 0x6c, 0x95, 0x22, 0x55, 0x9d, 0x29,
    0x00, 0xb5, 0x4c, 0x5b, 0xa5, 0x63, 0x31, 0x41,
    0x13, 0x0a, 0xea, 0x39, 0x78, 0x02, 0x6d, 0x62
};

BYTE g_rgbData[] = {0x01, 0x02, 0x03, 0x04,    0x05, 0x06, 0x07, 0x08};


EXTERN_C
__declspec(dllexport)
int WINAPI DiffieHellman(int argc, _TCHAR * argv[])
/*
Diffie-Hellman Keys
01/08/2021
11 minutes to read

Generating Diffie-Hellman Keys
Exchanging Diffie-Hellman Keys
Exporting a Diffie-Hellman Private Key
Example Code
Generating Diffie-Hellman Keys
To generate a Diffie-Hellman key, perform the following steps:

Call the CryptAcquireContext function to get a handle to the Microsoft Diffie-Hellman Cryptographic Provider.

Generate the new key. 
There are two ways to accomplish this—by having CryptoAPI generate all new values for G, P, 
and X or by using existing values for G and P, and generating a new value for X.

To generate the key by generating all new values

Call the CryptGenKey function, passing either CALG_DH_SF (store and forward) or CALG_DH_EPHEM (ephemeral) in the Algid parameter. The key will be generated using new, random values for G and P, a newly calculated value for X, and its handle will be returned in the phKey parameter.
The new key is now ready for use. The values of G and P must be sent to the recipient along with the key (or sent by some other method) when doing a key exchange.
To generate the key by using predefined values for G and P

Call CryptGenKey passing either CALG_DH_SF (store and forward) or CALG_DH_EPHEM (ephemeral) in the Algid parameter and CRYPT_PREGEN for the dwFlags parameter. A key handle will be generated and returned in the phKey parameter.
Initialize a CRYPT_DATA_BLOB structure with the pbData member set to the P value. The BLOB contains no header information and the pbData member is in little-endian format.
The value of P is set by calling the CryptSetKeyParam function, passing the key handle retrieved in step a in the hKey parameter, the KP_P flag in the dwParam parameter, and a pointer to the structure that contains the value of P in the pbData parameter.
Initialize a CRYPT_DATA_BLOB structure with the pbData member set to the G value. The BLOB contains no header information and the pbData member is in little-endian format.
The value of G is set by calling the CryptSetKeyParam function, passing the key handle retrieved in step a in the hKey parameter, the KP_G flag in the dwParam parameter, and a pointer to the structure that contains the value of G in the pbData parameter.
The value of X is generated by calling the CryptSetKeyParam function, passing the key handle retrieved in step a in the hKey parameter, the KP_X flag in the dwParam parameter, and NULL in the pbData parameter.
If all the function calls succeeded, the Diffie-Hellman public key is ready for use.
When the key is no longer needed, destroy it by passing the key handle to the CryptDestroyKey function.

If CALG_DH_SF was specified in the previous procedures, the key values are persisted to storage with each call to CryptSetKeyParam. The G and P values can then be retrieved by using the CryptGetKeyParam function. Some CSPs may have hard-coded G and P values. In this case a NTE_FIXEDPARAMETER error will be returned if CryptSetKeyParam is called with KP_G or KP_P specified in the dwParam parameter. If CryptDestroyKey is called, the handle to the key is destroyed, but the key values are retained in the CSP. However, if CALG_DH_EPHEM was specified, the handle to the key is destroyed, and all values are cleared from the CSP.

Exchanging Diffie-Hellman Keys
The purpose of the Diffie-Hellman algorithm is to make it possible for two or more parties to create and share an identical, secret session key by sharing information over a network that is not secure. The information that gets shared over the network is in the form of a couple of constant values and a Diffie-Hellman public key. The process used by two key-exchange parties is as follows:

Both parties agree to the Diffie-Hellman parameters which are a prime number (P) and a generator number (G).
Party 1 sends its Diffie-Hellman public key to party 2.
Party 2 computes the secret session key by using the information contained in its private key and party 1's public key.
Party 2 sends its Diffie-Hellman public key to party 1.
Party 1 computes the secret session key by using the information contained in its private key and party 2's public key.
Both parties now have the same session key, which can be used for encrypting and decrypting data. The steps necessary for this are shown in the following procedure.
To prepare a Diffie-Hellman public key for transmission

Call the CryptAcquireContext function to get a handle to the Microsoft Diffie-Hellman Cryptographic Provider.
Create a Diffie-Hellman key by calling the CryptGenKey function to create a new key, or by calling the CryptGetUserKey function to retrieve an existing key.
Get the size needed to hold the Diffie-Hellman key BLOB by calling the CryptExportKey, passing NULL for the pbData parameter. The required size will be returned in pdwDataLen.
Allocate memory for the key BLOB.
Create a Diffie-Hellman public key BLOB by calling the CryptExportKey function, passing PUBLICKEYBLOB in the dwBlobType parameter and the handle to the Diffie-Hellman key in the hKey parameter. This function call causes the calculation of the public key value, (G^X) mod P.
If all the preceding function calls were successful, the Diffie-Hellman public key BLOB is now ready to be encoded and transmitted.
To import a Diffie-Hellman public key and calculate the secret session key

Call the CryptAcquireContext function to get a handle to the Microsoft Diffie-Hellman Cryptographic Provider.
Create a Diffie-Hellman key by calling the CryptGenKey function to create a new key, or by calling the CryptGetUserKey function to retrieve an existing key.
To import the Diffie-Hellman public key into the CSP, call the CryptImportKey function, passing a pointer to the public key BLOB in the pbData parameter, the length of the BLOB in the dwDataLen parameter, and the handle to the Diffie-Hellman key in the hPubKey parameter. This causes the calculation, (Y^X) mod P, to be performed, thus creating the shared, secret key and completing the key exchange. This function call returns a handle to the new, secret, session key in the hKey parameter.
At this point, the imported Diffie-Hellman is of type CALG_AGREEDKEY_ANY. Before the key can be used, it must be converted into a session key type. This is accomplished by calling the CryptSetKeyParam function with dwParam set to KP_ALGID and with pbData set to a pointer to a ALG_ID value that represents a session key, such as CALG_RC4. The key must be converted before using the shared key in the CryptEncrypt or CryptDecrypt function. Calls made to either of these functions prior to converting the key type will fail.
The secret session key is now ready to be used for encryption or decryption.
When the key is no longer needed, destroy the key handle by calling the CryptDestroyKey function.
Exporting a Diffie-Hellman Private Key
To export a Diffie-Hellman private key, perform the following steps:

Call the CryptAcquireContext function to get a handle to the Microsoft Diffie-Hellman Cryptographic Provider.
Create a Diffie-Hellman key by calling the CryptGenKey function to create a new key, or by calling the CryptGetUserKey function to retrieve an existing key.
Create a Diffie-Hellman private key BLOB by calling the CryptExportKey function, passing PRIVATEKEYBLOB in the dwBlobType parameter and the handle to the Diffie-Hellman key in the hKey parameter.
When the key handle is no longer needed, call the CryptDestroyKey function to destroy the key handle.

Example Code
The following example shows how to create, export, import, and use a Diffie-Hellman key to perform a key exchange.

https://docs.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-keys
*/
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    BOOL fReturn;
    HCRYPTPROV hProvParty1 = NULL;
    HCRYPTPROV hProvParty2 = NULL;
    DATA_BLOB P;
    DATA_BLOB G;
    HCRYPTKEY hPrivateKey1 = NULL;
    HCRYPTKEY hPrivateKey2 = NULL;
    PBYTE pbKeyBlob1 = NULL;
    PBYTE pbKeyBlob2 = NULL;
    HCRYPTKEY hSessionKey1 = NULL;
    HCRYPTKEY hSessionKey2 = NULL;
    PBYTE pbData = NULL;
    DWORD dwLength;
    ALG_ID Algid;

    /************************
    Construct data BLOBs for the prime and generator. The P and G
    values, represented by the g_rgbPrime and g_rgbGenerator arrays
    respectively, are shared values that have been agreed to by both parties.
    ************************/
    P.cbData = DHKEYSIZE / 8;
    P.pbData = (BYTE *)(g_rgbPrime);

    G.cbData = DHKEYSIZE / 8;
    G.pbData = (BYTE *)(g_rgbGenerator);

    /************************
    Create the private Diffie-Hellman key for party 1.
    ************************/
    // Acquire a provider handle for party 1.
    fReturn = CryptAcquireContext(&hProvParty1, NULL, MS_ENH_DSS_DH_PROV, PROV_DSS_DH, CRYPT_VERIFYCONTEXT);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Create an ephemeral private key for party 1.
    fReturn = CryptGenKey(
        hProvParty1,
        CALG_DH_EPHEM,
        DHKEYSIZE << 16 | CRYPT_EXPORTABLE | CRYPT_PREGEN,
        &hPrivateKey1);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Set the prime for party 1's private key.
    fReturn = CryptSetKeyParam(hPrivateKey1, KP_P, (PBYTE)&P, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Set the generator for party 1's private key.
    fReturn = CryptSetKeyParam(hPrivateKey1, KP_G, (PBYTE)&G, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Generate the secret values for party 1's private key.
    fReturn = CryptSetKeyParam(hPrivateKey1, KP_X, NULL, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Create the private Diffie-Hellman key for party 2.
    ************************/
    // Acquire a provider handle for party 2.
    fReturn = CryptAcquireContext(&hProvParty2, NULL, MS_ENH_DSS_DH_PROV, PROV_DSS_DH, CRYPT_VERIFYCONTEXT);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Create an ephemeral private key for party 2.
    fReturn = CryptGenKey(
        hProvParty2,
        CALG_DH_EPHEM,
        DHKEYSIZE << 16 | CRYPT_EXPORTABLE | CRYPT_PREGEN,
        &hPrivateKey2);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Set the prime for party 2's private key.
    fReturn = CryptSetKeyParam(hPrivateKey2, KP_P, (PBYTE)&P, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Set the generator for party 2's private key.
    fReturn = CryptSetKeyParam(hPrivateKey2, KP_G, (PBYTE)&G, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Generate the secret values for party 2's private key.
    fReturn = CryptSetKeyParam(hPrivateKey2, KP_X, NULL, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Export Party 1's public key.
    ************************/
    // Public key value, (G^X) mod P is calculated.
    DWORD dwDataLen1;

    // Get the size for the key BLOB.
    fReturn = CryptExportKey(hPrivateKey1, NULL, PUBLICKEYBLOB, 0, NULL, &dwDataLen1);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Allocate the memory for the key BLOB.
    if (!(pbKeyBlob1 = (PBYTE)malloc(dwDataLen1))) {
        goto ErrorExit;
    }

    // Get the key BLOB.
    fReturn = CryptExportKey(hPrivateKey1, 0, PUBLICKEYBLOB, 0, pbKeyBlob1, &dwDataLen1);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Export Party 2's public key.
    ************************/
    // Public key value, (G^X) mod P is calculated.
    DWORD dwDataLen2;

    // Get the size for the key BLOB.
    fReturn = CryptExportKey(hPrivateKey2, NULL, PUBLICKEYBLOB, 0, NULL, &dwDataLen2);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Allocate the memory for the key BLOB.
    if (!(pbKeyBlob2 = (PBYTE)malloc(dwDataLen2))) {
        goto ErrorExit;
    }

    // Get the key BLOB.
    fReturn = CryptExportKey(hPrivateKey2, 0, PUBLICKEYBLOB, 0, pbKeyBlob2, &dwDataLen2);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Party 1 imports party 2's public key.
    The imported key will contain the new shared secret
    key (Y^X) mod P.
    ************************/
    fReturn = CryptImportKey(hProvParty1, pbKeyBlob2, dwDataLen2, hPrivateKey1, 0, &hSessionKey2);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Party 2 imports party 1's public key.
    The imported key will contain the new shared secret
    key (Y^X) mod P.
    ************************/
    fReturn = CryptImportKey(hProvParty2, pbKeyBlob1, dwDataLen1, hPrivateKey2, 0, &hSessionKey1);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Convert the agreed keys to symmetric keys. They are currently of
    the form CALG_AGREEDKEY_ANY. Convert them to CALG_RC4.
    ************************/
    Algid = CALG_RC4;

    // Enable the party 1 public session key for use by setting the 
    // ALGID.
    fReturn = CryptSetKeyParam(hSessionKey1, KP_ALGID, (PBYTE)&Algid, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    // Enable the party 2 public session key for use by setting the ALGID.
    fReturn = CryptSetKeyParam(hSessionKey2, KP_ALGID, (PBYTE)&Algid, 0);
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Encrypt some data with party 1's session key.
    ************************/
    // Get the size.
    dwLength = sizeof(g_rgbData);
    fReturn = CryptEncrypt(hSessionKey1, 0, TRUE, 0, NULL, &dwLength, sizeof(g_rgbData));
    if (!fReturn) {
        goto ErrorExit;
    }

    // Allocate a buffer to hold the encrypted data.
    pbData = (PBYTE)malloc(dwLength);
    if (!pbData) {
        goto ErrorExit;
    }

    // Copy the unencrypted data to the buffer. The data will be 
    // encrypted in place.
    memcpy(pbData, g_rgbData, sizeof(g_rgbData));

    // Encrypt the data.
    dwLength = sizeof(g_rgbData);
    fReturn = CryptEncrypt(hSessionKey1, 0, TRUE, 0, pbData, &dwLength, sizeof(g_rgbData));
    if (!fReturn) {
        goto ErrorExit;
    }

    /************************
    Decrypt the data with party 2's session key.
    ************************/
    dwLength = sizeof(g_rgbData);
    fReturn = CryptDecrypt(hSessionKey2, 0, TRUE, 0, pbData, &dwLength);
    if (!fReturn) {
        goto ErrorExit;
    }

ErrorExit:
    if (pbData) {
        free(pbData);
        pbData = NULL;
    }

    if (hSessionKey2) {
        CryptDestroyKey(hSessionKey2);
        hSessionKey2 = NULL;
    }

    if (hSessionKey1) {
        CryptDestroyKey(hSessionKey1);
        hSessionKey1 = NULL;
    }

    if (pbKeyBlob2) {
        free(pbKeyBlob2);
        pbKeyBlob2 = NULL;
    }

    if (pbKeyBlob1) {
        free(pbKeyBlob1);
        pbKeyBlob1 = NULL;
    }

    if (hPrivateKey2) {
        CryptDestroyKey(hPrivateKey2);
        hPrivateKey2 = NULL;
    }

    if (hPrivateKey1) {
        CryptDestroyKey(hPrivateKey1);
        hPrivateKey1 = NULL;
    }

    if (hProvParty2) {
        CryptReleaseContext(hProvParty2, 0);
        hProvParty2 = NULL;
    }

    if (hProvParty1) {
        CryptReleaseContext(hProvParty1, 0);
        hProvParty1 = NULL;
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////

