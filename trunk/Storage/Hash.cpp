#include "pch.h"
#include "Hash.h"


#pragma warning(disable:28182)
#pragma warning(disable:28183)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Hashing
2018/05/31

The following procedures and examples deal with the creation, encoding, decoding and signing of hashes:

Creating a CALG_SSL3_SHAMD5 Hash
Creating an HMAC
Example C Program: Creating and Hashing a Session Key
Example C Program: Duplicating a Hash
Encoding and Decoding a Hashed Message
Example C Program: Encoding and Decoding a Hashed Message
Example C Program: Signing a Hash and Verifying the Hash Signature
Example C Program: Creating an MD5 Hash From File Content
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


int CreatingHMAC()
/*
Example C Program: Creating an HMAC
2018/05/31

A hashed message authentication checksum (HMAC) is typically used to verify that a message has not been changed during transit.
Both parties to the message must have a shared secret key.
The sender combines the key and the message into a string,
creates a digest of the string by using an algorithm such as SHA-1 or MD5,
and transmits the message and the digest.
The receiver combines the shared key with the message, applies the appropriate algorithm,
and compares the digest thus obtained with that transmitted by the sender.
If the digests are exactly the same, the message was not tampered with.

This example demonstrates the following tasks and CryptoAPI functions:

Acquiring a handle to a cryptographic service provider by calling CryptAcquireContext.
Deriving a symmetric key from a byte string by calling CryptCreateHash, CryptHashData, and CryptDeriveKey.
Using the symmetric key to create an HMAC hash object by calling CryptCreateHash and CryptSetHashParam.
Hashing a message by calling CryptHashData.
Retrieving the hash by calling CryptGetHashParam.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program--creating-an-hmac
*/
{
    // Declare variables.
    // hProv:           Handle to a cryptographic service provider (CSP). 
    //                  This example retrieves the default provider for the PROV_RSA_FULL provider type.  
    // hHash:           Handle to the hash object needed to create a hash.
    // hKey:            Handle to a symmetric key. This example creates a key for the RC4 algorithm.
    // hHmacHash:       Handle to an HMAC hash.
    // pbHash:          Pointer to the hash.
    // dwDataLen:       Length, in bytes, of the hash.
    // Data1:           Password string used to create a symmetric key.
    // Data2:           Message string to be hashed.
    // HmacInfo:        Instance of an HMAC_INFO structure that contains information about the HMAC hash.
    HCRYPTPROV  hProv = NULL;
    HCRYPTHASH  hHash = NULL;
    HCRYPTKEY   hKey = NULL;
    HCRYPTHASH  hHmacHash = NULL;
    PBYTE       pbHash = NULL;
    DWORD       dwDataLen = 0;
    BYTE        Data1[] = {0x70,0x61,0x73,0x73,0x77,0x6F,0x72,0x64};
    BYTE        Data2[] = {0x6D,0x65,0x73,0x73,0x61,0x67,0x65};
    HMAC_INFO   HmacInfo;

    // Zero the HMAC_INFO structure and use the SHA1 algorithm for hashing.
    ZeroMemory(&HmacInfo, sizeof(HmacInfo));
    HmacInfo.HashAlgid = CALG_SHA1;

    // Acquire a handle to the default RSA cryptographic service provider.
    if (!CryptAcquireContext(
        &hProv,                   // handle of the CSP
        NULL,                     // key container name
        NULL,                     // CSP name
        PROV_RSA_FULL,            // provider type
        CRYPT_VERIFYCONTEXT))     // no key access is requested
    {
        printf(" Error in AcquireContext 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    // Derive a symmetric key from a hash object by performing the
    // following steps:
    //    1. Call CryptCreateHash to retrieve a handle to a hash object.
    //    2. Call CryptHashData to add a text string (password) to the hash object.
    //    3. Call CryptDeriveKey to create the symmetric key from the
    //       hashed password derived in step 2.
    // You will use the key later to create an HMAC hash object. 

    if (!CryptCreateHash(
        hProv,                    // handle of the CSP
        CALG_SHA1,                // hash algorithm to use
        0,                        // hash key
        0,                        // reserved
        &hHash))                  // address of hash object handle
    {
        printf("Error in CryptCreateHash 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    if (!CryptHashData(
        hHash,                    // handle of the hash object
        Data1,                    // password to hash
        sizeof(Data1),            // number of bytes of data to add
        0))                       // flags
    {
        printf("Error in CryptHashData 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    if (!CryptDeriveKey(
        hProv,                    // handle of the CSP
        CALG_RC4,                 // algorithm ID
        hHash,                    // handle to the hash object
        0,                        // flags
        &hKey))                   // address of the key handle
    {
        printf("Error in CryptDeriveKey 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    // Create an HMAC by performing the following steps:
    //    1. Call CryptCreateHash to create a hash object and retrieve a handle to it.
    //    2. Call CryptSetHashParam to set the instance of the HMAC_INFO structure into the hash object.
    //    3. Call CryptHashData to compute a hash of the message.
    //    4. Call CryptGetHashParam to retrieve the size, in bytes, of the hash.
    //    5. Call malloc to allocate memory for the hash.
    //    6. Call CryptGetHashParam again to retrieve the HMAC hash.

    if (!CryptCreateHash(
        hProv,                    // handle of the CSP.
        CALG_HMAC,                // HMAC hash algorithm ID
        hKey,                     // key for the hash (see above)
        0,                        // reserved
        &hHmacHash))              // address of the hash handle
    {
        printf("Error in CryptCreateHash 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    if (!CryptSetHashParam(
        hHmacHash,                // handle of the HMAC hash object
        HP_HMAC_INFO,             // setting an HMAC_INFO object
        (BYTE *)&HmacInfo,         // the HMAC_INFO object
        0))                       // reserved
    {
        printf("Error in CryptSetHashParam 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    if (!CryptHashData(
        hHmacHash,                // handle of the HMAC hash object
        Data2,                    // message to hash
        sizeof(Data2),            // number of bytes of data to add
        0))                       // flags
    {
        printf("Error in CryptHashData 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    // Call CryptGetHashParam twice. Call it the first time to retrieve
    // the size, in bytes, of the hash. Allocate memory. 
    // Then call CryptGetHashParam again to retrieve the hash value.

    if (!CryptGetHashParam(
        hHmacHash,                // handle of the HMAC hash object
        HP_HASHVAL,               // query on the hash value
        NULL,                     // filled on second call
        &dwDataLen,               // length, in bytes, of the hash
        0)) {
        printf("Error in CryptGetHashParam 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    pbHash = (BYTE *)malloc(dwDataLen);
    if (NULL == pbHash) {
        printf("unable to allocate memory\n");
        goto ErrorExit;
    }

    if (!CryptGetHashParam(
        hHmacHash,                 // handle of the HMAC hash object
        HP_HASHVAL,                // query on the hash value
        pbHash,                    // pointer to the HMAC hash value
        &dwDataLen,                // length, in bytes, of the hash
        0)) {
        printf("Error in CryptGetHashParam 0x%08x \n", GetLastError());
        goto ErrorExit;
    }

    // Print the hash to the console.
    printf("The hash is:  ");
    for (DWORD i = 0; i < dwDataLen; i++) {
        printf("%2.2x ", pbHash[i]);
    }
    printf("\n");

    // Free resources.
ErrorExit:
    if (hHmacHash)
        CryptDestroyHash(hHmacHash);
    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    if (pbHash)
        free(pbHash);
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//  Copyright (C) Microsoft. All rights reserved.
//  
//  CreateAndHashSessionKey.cpp : Defines the entry point for the application.


void CreatingHashingSessionKey()
/*
Example C Program: Creating and Hashing a Session Key
2018/05/31

The following example creates and hashes a session key that can be used to encrypt a message, text, or file.

This example also shows using the following CryptoAPI functions:

CryptAcquireContext to acquire a cryptographic service provider.
CryptCreateHash to create an empty hash object.
CryptGenKey to create a random session key.
CryptHashSessionKey to hash the session key created.
CryptDestroyHash to destroy the hash.
CryptDestroyKey to destroy the key created.
CryptReleaseContext to release the CSP.
This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-creating-and-hashing-a-session-key
*/
{
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    // Acquire a cryptographic provider context handle.
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("CryptAcquireContext complete. \n");
    } else {
        MyHandleError("Acquisition of context failed.");
    }

    // Create a hash object.
    if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        printf("An empty hash object has been created. \n");
    } else {
        MyHandleError("Error during CryptBeginHash!\n");
    }

    // Create a random session key.
    if (CryptGenKey(hCryptProv, CALG_RC2, CRYPT_EXPORTABLE, &hKey)) {
        printf("A random session key has been created. \n");
    } else {
        MyHandleError("Error during CryptGenKey!\n");
    }

    // Compute the cryptographic hash on the key object.
    if (CryptHashSessionKey(hHash, hKey, 0)) {
        printf("The session key has been hashed. \n");
    } else {
        MyHandleError("Error during CryptHashSessionKey!\n");
    }

    /*
    Use the hash of the key object. For instance, additional data
    could be hashed and sent in a message to several recipients. The
    recipients will be able to verify who the message originator is
    if the key used is also exported to them.
    */

    // Clean up.

    // Destroy the hash object.
    if (hHash) {
        if (!(CryptDestroyHash(hHash))) {
            MyHandleError("Error during CryptDestroyHash");
        }
    }

    // Destroy the session key.
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            MyHandleError("Error during CryptDestroyKey");
        }
    }

    // Release the provider.
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0))) {
            MyHandleError("Error during CryptReleaseContext");
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void Get_And_Print_Hash(HCRYPTHASH hOHash)
// Define the function Get_And_Print_Hash.
{
    // Declare and initialize local variables.
    HCRYPTHASH   hHash;
    BYTE * pbHash;
    DWORD        dwHashLen;
    DWORD        dwHashLenSize = sizeof(DWORD);
    DWORD        i;

    // Duplicate the hash passed in.
    // The hash is duplicated to leave the original hash intact.
    if (CryptDuplicateHash(hOHash, NULL, 0, &hHash)) {
        // It worked. Do nothing.
    } else {
        MyHandleError("Error during CryptDuplicateHash.");
    }

    if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&dwHashLen, &dwHashLenSize, 0)) {
        // It worked. Do nothing.
    } else {
        MyHandleError("CryptGetHashParam failed to get size.");
    }

    if (pbHash = (BYTE *)malloc(dwHashLen)) {
        // It worked. Do nothing.
    } else {
        MyHandleError("Allocation failed.");
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
        // Print the hash value.
        printf("The hash is:  ");
        for (i = 0; i < dwHashLen; i++) {
            printf("%02x ", pbHash[i]);
        }
        printf("\n");
    } else {
        MyHandleError("Error during reading hash value.");
    }

    free(pbHash);
    if (CryptDestroyHash(hHash)) {
        // It worked. Do nothing.
    } else {
        MyHandleError("ERROR - CryptDestroyHash");
    }
} // end Get_And_Print_Hash


void DuplicatingHash(void)
/*
Example C Program: Duplicating a Hash
2018/05/31

The following example creates and duplicates a hash of some text.
It then adds additional text to the original hash and different text to the duplicate.

This example uses the following CryptoAPI functions:

CryptAcquireContext
CryptCreateHash
CryptHashData
CryptDuplicateHash
CryptGetHashParam
CryptDestroyHash
CryptReleaseContext
This example uses the function MyHandleError. Code for this function is included at the end of the example.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-duplicating-a-hash
*/
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Declare and initialize variables.
    HCRYPTPROV   hCryptProv = NULL;
    HCRYPTHASH   hOriginalHash;
    HCRYPTHASH   hDuplicateHash;

    // Acquire a cryptographic provider context handle.
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("CryptAcquireContext succeeded. \n");
    } else {
        MyHandleError("Error during CryptAcquireContext!");
    }

    // Create a hash.
    if (CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hOriginalHash)) {
        printf("An empty hash object has been created. \n");
    } else {
        MyHandleError("Error during CryptCreateHash.");
    }

    // Hash a BYTE string.
    if (CryptHashData(hOriginalHash, (BYTE *)"Some Common Data", sizeof("Some Common Data"), 0)) {
        printf("An original hash has been created. \n");
    } else {
        MyHandleError("Error during CryptHashData.");
    }

    // Duplicate the hash.
    if (CryptDuplicateHash(hOriginalHash, NULL, 0, &hDuplicateHash)) {
        printf("The hash has been duplicated. \n");
    } else {
        MyHandleError("Error during CryptDuplicateHash.");
    }

    printf("The original hash -- phase 1.\n");
    Get_And_Print_Hash(hOriginalHash);

    printf("The duplicate hash -- phase 1.\n");
    Get_And_Print_Hash(hDuplicateHash);

    // Hash some data with the original hash.
    if (CryptHashData(hOriginalHash, (BYTE *)"Some Data", sizeof("Some Data"), 0)) {
        printf("Additional data has been hashed with the original. \n");
    } else {
        MyHandleError("Error during CryptHashData.");
    }

    // Hash other data with the duplicate hash.
    if (CryptHashData(hDuplicateHash, (BYTE *)"Other Data", sizeof("Other Data"), 0)) {
        printf("More data has been hashed with the duplicate. \n");
    } else {
        MyHandleError("Error during CryptHashData.");
    }

    printf("The original hash -- phase 2.\n");
    Get_And_Print_Hash(hOriginalHash);

    printf("The duplicate hash -- phase 2.\n");
    Get_And_Print_Hash(hDuplicateHash);

    // Destroy the original hash.
    if (CryptDestroyHash(hOriginalHash)) {
        printf("The original hash has been destroyed. \n");
    } else {
        MyHandleError("ERROR during CryptDestroyHash");
    }

    // Destroy the duplicate hash.
    if (CryptDestroyHash(hDuplicateHash)) {
        printf("The duplicate hash has been destroyed. \n");
    } else {
        MyHandleError("Error -- CryptDestroyHash");
    }

    // Release the CSP.
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);

    printf("The program ran to completion without error. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void EncodingAndDecodingHashedMessage(void)
/*
Example C Program: Encoding and Decoding a Hashed Message
2018/05/31

The following example hashes and encodes a text message, and then decodes and verifies the message.

Although, for simplicity, the two different functions have been combined in this example,
in a more realistic setting the two parts would be used separately.

This example illustrates the following tasks and CryptoAPI functions:

Calling CryptAcquireContext to acquire a CSP provider.
Using CryptMsgCalculateEncodedLength to calculate the length of the encoded message.
Allocating memory for a buffer to hold the encoded data.
Opening a message to encode using CryptMsgOpenToEncode.
Adding content to the message to encode using CryptMsgUpdate.
Using CryptMsgGetParam to copy the encoded message to the allocated buffer.
Opening a message to decode using CryptMsgOpenToDecode.
Adding the encoded message to the message to decode using CryptMsgUpdate.
Creating a duplicate pointer to the message using CryptMsgDuplicate.
Checking the message type with CryptMsgGetParam.
Using CryptMsgGetParam to decode the message.
Verifying the hash using CryptMsgControl.
Using CryptMsgClose to release the message handle.
Using CryptReleaseContext to release the CSP.
This example uses the function MyHandleError. Code for this function is included with the sample.

Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-encoding-and-decoding-a-hashed-message
*/
{
    //  Copyright (C) Microsoft.  All rights reserved.
    //  Declare and initialize variables. This includes creating a pointer to the message content. 
    //  In real situations, 
    //  the message content will usually exist somewhere and a pointer to it will get passed to the application. 

    BYTE * pbContent = (BYTE *)"A razzle-dazzle hashed message \n"
        "Hashing is better than trashing. \n";    // The message
    DWORD cbContent = (DWORD)strlen((char *)pbContent) + 1;  // Size of message
                                                    // including the final NULL.
    HCRYPTPROV hCryptProv;                          // CSP handle
    DWORD HashAlgSize;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CMSG_HASHED_ENCODE_INFO HashedEncodeInfo;
    DWORD cbEncodedBlob;
    BYTE * pbEncodedBlob;
    HCRYPTMSG hMsg;
    HCRYPTMSG hDupMsg;
    //  Variables to be used in decoding.
    DWORD cbData = sizeof(DWORD);
    DWORD dwMsgType;
    DWORD cbDecoded = 0;
    BYTE * pbDecoded;

    //  Begin processing.
    printf("Begin processing. \n");
    printf("The message to be hashed and encoded is: \n");
    printf("%s\n", pbContent);    // Display original message.
    printf("The starting message length is %d\n", cbContent);

    // Acquire a cryptographic provider context handle.
    if (CryptAcquireContext(
        &hCryptProv,     // Address for the handle. 
        NULL,            // Use the current user's logon name.
        NULL,            // Use the default provider.
        PROV_RSA_FULL,   // Provider type.
        0))              // Zero allows access to private keys.
    {
        printf("A CSP context has been acquired. \n");
    } else {
        MyHandleError("CryptAcquireContext failed.");
    }

    // The function succeeded; hCryptProv is the CSP handle.

    // Initialize the algorithm identifier structure.
    HashAlgSize = sizeof(HashAlgorithm);
    memset(&HashAlgorithm, 0, HashAlgSize);   // Initialize to zero.
    HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5;   // Then set the necessary member.

    // Initialize the CMSG_HASHED_ENCODE_INFO structure.
    memset(&HashedEncodeInfo, 0, sizeof(CMSG_HASHED_ENCODE_INFO));
    HashedEncodeInfo.cbSize = sizeof(CMSG_HASHED_ENCODE_INFO);
    HashedEncodeInfo.hCryptProv = hCryptProv;
    HashedEncodeInfo.HashAlgorithm = HashAlgorithm;
    HashedEncodeInfo.pvHashAuxInfo = NULL;

    // Get the size of the encoded message BLOB.
    if (cbEncodedBlob = CryptMsgCalculateEncodedLength(
        MY_ENCODING_TYPE,     // Message encoding type
        0,                    // Flags
        CMSG_HASHED,          // Message type
        &HashedEncodeInfo,    // Pointer to structure
        NULL,                 // Inner content object ID
        cbContent))           // Size of content
    {
        printf("The length to be allocated is %d bytes.\n", cbEncodedBlob);
    } else {
        MyHandleError("Getting cbEncodedBlob length failed");
    }

    // Allocate memory for the encoded BLOB.
    if (pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob)) {
        printf("%d bytes of memory have been allocated.\n", cbEncodedBlob);
    } else {
        MyHandleError("Malloc operation failed.");
    }

    // Open a message to encode.
    if (hMsg = CryptMsgOpenToEncode(
        MY_ENCODING_TYPE,        // Encoding type
        0,                       // Flags
        CMSG_HASHED,             // Message type
        &HashedEncodeInfo,       // Pointer to structure
        NULL,                    // Inner content object ID
        NULL))                   // Stream information (not used)
    {
        printf("The message to encode has been opened. \n");
    } else {
        MyHandleError("OpenToEncode failed");
    }

    // Update the message with the data.
    if (CryptMsgUpdate(
        hMsg,          // Handle to the message
        pbContent,     // Pointer to the content
        cbContent,     // Size of the content
        TRUE))         // Last call
    {
        printf("Data has been added to the message to encode. \n");
    } else {
        MyHandleError("MsgUpdate failed");
    }

    // Create a duplicate of the message.
    if (hDupMsg = CryptMsgDuplicate(hMsg)) {
        printf("The message has been duplicated.\n");
    } else {
        MyHandleError("Duplication of the message failed.");
    }

    // Get the resulting message from the duplicate of the message.
    if (CryptMsgGetParam(
        hDupMsg,                  // Handle to the message
        CMSG_CONTENT_PARAM,       // Parameter type
        0,                        // Index
        pbEncodedBlob,            // Pointer to the BLOB
        &cbEncodedBlob))          // Size of the BLOB
    {
        printf("Message encoded successfully. \n");
    } else {
        MyHandleError("MsgGetParam failed");
    }

    // Close both messages to prepare for decoding.
    CryptMsgClose(hMsg);
    CryptMsgClose(hDupMsg);

    // The following code decodes the hashed message.
    // Usually, this would be in a separate program and the encoded,
    // hashed data would be input from a file, from an email message, or from some other source.
    //
    // The variables used in this code have already been declared and initialized.

    // Open the  message for decoding.
    if (hMsg = CryptMsgOpenToDecode(
        MY_ENCODING_TYPE,       // Encoding type
        0,                      // Flags
        0,                      // Message type 
                                // (get from message)
        hCryptProv,             // Cryptographic provider
        NULL,                   // Recipient information
        NULL))                  // Stream information
    {
        printf("The message has been opened for decoding. \n");
    } else {
        MyHandleError("OpenToDecode failed");
    }

    // Update the message with the encoded BLOB. 
    if (CryptMsgUpdate(
        hMsg,             // Handle to the message
        pbEncodedBlob,    // Pointer to the encoded BLOB
        cbEncodedBlob,    // Size of the encoded BLOB
        TRUE))            // Last call
    {
        printf("The encoded data is added to the message to decode. \n");
    } else {
        MyHandleError("Decode MsgUpdate failed");
    }

    // Get the message type.
    if (CryptMsgGetParam(
        hMsg,               // Handle to the message
        CMSG_TYPE_PARAM,    // Parameter type
        0,                  // Index
        &dwMsgType,         // Address for returned information
        &cbData))           // Size of the returned information
    {
        printf("The message type has been obtained. \n");
    } else {
        MyHandleError("Decode CMSG_TYPE_PARAM failed");
    }

    // Some applications may need to use a switch statement here
    // and process the message differently, depending on the message type.
    if (dwMsgType == CMSG_HASHED) {
        printf("The message is a hashed message. Proceed. \n");
    } else {
        MyHandleError("Wrong message type");
    }

    // Get the size of the content.
    if (CryptMsgGetParam(
        hMsg,                   // Handle to the message
        CMSG_CONTENT_PARAM,     // Parameter type
        0,                      // Index
        NULL,                   // Address for returned information
        &cbDecoded))            // Size of the returned information
    {
        printf("The length %d of the message obtained. \n", cbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM failed");
    }

    // Allocate memory.
    if (pbDecoded = (BYTE *)malloc(cbDecoded)) {
        printf("Memory for the decoded message has been allocated.\n");
    } else {
        MyHandleError("Decoding memory allocation failed");
    }

    // Copy the decoded message into the buffer just allocated.
    if (CryptMsgGetParam(
        hMsg,                    // Handle to the message
        CMSG_CONTENT_PARAM,      // Parameter type
        0,                       // Index
        pbDecoded,               // Address for returned information
        &cbDecoded))             // Size of the returned information
    {
        printf("Message decoded successfully \n");
        printf("The decoded message is \n%s\n", (LPSTR)pbDecoded);
    } else {
        MyHandleError("Decoding CMSG_CONTENT_PARAM #2 failed");
    }

    // Verify the hash.
    if (CryptMsgControl(
        hMsg,                        // Handle to the message
        0,                           // Flags
        CMSG_CTRL_VERIFY_HASH,       // Control type
        NULL))                       // Pointer not used
    {
        printf("Verification of hash succeeded. \n");
        printf("The data has not been tampered with.\n");
    } else {
        printf("Verification of hash failed. Something changed this message .\n");
    }

    printf("Test program completed without error. \n");

    // Clean up

    if (pbEncodedBlob)
        free(pbEncodedBlob);
    if (pbDecoded)
        free(pbDecoded);

    CryptMsgClose(hMsg);

    // Release the CSP.
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
DWORD WINAPI GetFileMd5Hash(LPCWSTR FileName)
/*
Example C Program: Creating an MD5 Hash from File Content
2018/05/31

The following example demonstrates using CryptoAPI to compute the MD5 hash of the contents of a file.
This example performs the computation on the contents of a file specified at run time.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content?redirectedfrom=MSDN
*/
{
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    // Logic to check usage goes here.

    hFile = CreateFile(FileName,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        dwStatus = GetLastError();
        printf("Error opening file %ls\nError: %d\n", FileName, dwStatus);
        return dwStatus;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)) {
        if (0 == cbRead) {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }
    }

    if (!bResult) {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        printf("MD5 hash of file %ls is: ", FileName);
        for (DWORD i = 0; i < cbHash; i++) {
            printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        }
        printf("\n");
    } else {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return dwStatus;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
The following examples describe how to perform specific cryptographic operations using CNG.

Creating a Hash with CNG
Signing Data with CNG
Encrypting Data with CNG
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
//
// Copyright (C) Microsoft. All rights reserved.


EXTERN_C
__declspec(dllexport)
void WINAPI HashDataByCNG(int argc, __in_ecount(argc) LPWSTR * wargv)
/*++
Abstract:
    Sample program for SHA 256 hashing using CNG

Creating a Hash with CNG
2018/05/31

A hash is a one way operation that is performed on a block of data to create a unique hash value that represents the contents of the data.
No matter when the hash is performed, the same hashing algorithm performed on the same data will always produce the same hash value.
If any of the data changes, the hash value will change appropriately.

Hashes are not useful for encrypting data because they are not intended to be used to reproduce the original data from the hash value.
Hashes are most useful to verify the integrity of the data when used with an asymmetric signing algorithm.
For example, if you hashed a text message, signed the hash,
and included the signed hash value with the original message,
the recipient could verify the signed hash, create the hash value for the received message,
and then compare this hash value with the signed hash value included with the original message.
If the two hash values are identical,
the recipient can be reasonably sure that the original message has not been modified.

The size of the hash value is fixed for a particular hashing algorithm.
What this means is that no matter how large or small the data block is,
the hash value will always be the same size.
As an example, the SHA256 hashing algorithm has a hash value size of 256 bits.

Creating a Hashing Object
Creating a Reusable Hashing Object
Duplicating a Hash Object
Creating a Hashing Object
To create a hash using CNG, perform the following steps:

Open an algorithm provider that supports the desired algorithm.
Typical hashing algorithms include MD2, MD4, MD5, SHA-1, and SHA256.
Call the BCryptOpenAlgorithmProvider function and
specify the appropriate algorithm identifier in the pszAlgId parameter.
The function returns a handle to the provider.

Perform the following steps to create the hashing object:

Obtain the size of the object by calling the BCryptGetProperty function to retrieve the BCRYPT_OBJECT_LENGTH property.
Allocate memory to hold the hash object.
Create the object by calling the BCryptCreateHash function.
Hash the data. This involves calling the BCryptHashData function one or more times.
Each call appends the specified data to the hash.

Perform the following steps to obtain the hash value:

Retrieve the size of the value by calling the BCryptGetProperty function to get the BCRYPT_HASH_LENGTH property.
Allocate memory to hold the value.
Retrieve the hash value by calling the BCryptFinishHash function.
After this function has been called, the hash object is no longer valid.
To complete this procedure, you must perform the following cleanup steps:

Close the hash object by passing the hash handle to the BCryptDestroyHash function.

Free the memory you allocated for the hash object.

If you will not be creating any more hash objects,
close the algorithm provider by passing the provider handle to the BCryptCloseAlgorithmProvider function.

If you will be creating more hash objects,
we suggest you reuse the algorithm provider rather than creating and
destroying the same type of algorithm provider many times.

When you have finished using the hash value memory, free it.

The following example shows how to create a hash value by using CNG.

https://docs.microsoft.com/zh-cn/windows/win32/seccng/creating-a-hash-with-cng
--*/
{
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL;
    static const BYTE rgbMsg[] = {0x61, 0x62, 0x63};

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(wargv);

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, (PBYTE)rgbMsg, sizeof(rgbMsg), 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    wprintf(L"Success!\n");

Cleanup:

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject) {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    if (pbHash) {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }
}


EXTERN_C
__declspec(dllexport)
BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize
)
/*++

Hash需要由调用者调用HeapFree释放。

https://docs.microsoft.com/zh-cn/windows/win32/seccng/creating-a-hash-with-cng
--*/
{
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0, cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    BOOL                    ret = FALSE;

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)HashSize, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    *Hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *HashSize);
    if (NULL == *Hash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }

    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, Data, DataSize, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, *Hash, *HashSize, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    ret = TRUE;

Cleanup:

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject) {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    //if (*Hash) {
    //    HeapFree(GetProcessHeap(), 0, *Hash);
    //}

    return ret;
}


EXTERN_C
__declspec(dllexport)
DWORD WINAPI GetFileHash(_In_ LPCWSTR lpFileName,
                         _In_z_ LPCWSTR pszAlgId,
                         _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                         _In_ ULONG * HashSize
)
/*


https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content?redirectedfrom=MSDN
*/
{
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    //HCRYPTPROV hProv = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    //DWORD cbHash = 0;
    //CHAR rgbDigits[] = "0123456789abcdef";
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0, cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;

    // Logic to check usage goes here.

    hFile = CreateFile(lpFileName,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        dwStatus = GetLastError();
        printf("Error opening file %ls\nError: %d\n", lpFileName, dwStatus);
        return dwStatus;
    }

        //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)HashSize, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    *Hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *HashSize);
    if (NULL == *Hash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)) {
        if (0 == cbRead) {
            break;
        }

        if (!NT_SUCCESS(status = BCryptHashData(hHash, rgbFile, cbRead, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
            goto Cleanup;
        }
    }

    if (!bResult) {
        dwStatus = GetLastError();
        return dwStatus;
    }

    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, *Hash, *HashSize, 0))) {//close the hash
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

Cleanup:

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject) {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    CloseHandle(hFile);

    return dwStatus;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
