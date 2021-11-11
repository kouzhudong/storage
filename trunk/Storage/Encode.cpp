#include "pch.h"
#include "Encode.h"


#pragma warning(disable:6001)
#pragma warning(disable:28182)
#pragma warning(disable:4477)
#pragma warning(disable:6302)
#pragma warning(disable:28183)
#pragma warning(disable:6387)
#pragma warning(disable:4996)
#pragma warning(disable:6029)
#pragma warning(disable:6011)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Signing Data
2018/05/31

The following sections deal with encoding and decoding signed data, including messages, certificates,
certificate revocation lists (CRLs), and certificate trust lists (CTLs):

Creating a Signed Message
Procedure for Signing Data
Verifying a Signed Message
Encoding Signed Data
Decoding Signed Data
Example C Program: Signing a Message and Verifying a Message Signature
Example C Program: Signing, Encoding, Decoding, and Verifying a Message
Example C Program: Encoding and Decoding a Message Using a Stream
Example C Program: Sending and Receiving a Signed and Encrypted Message
Example C Program: Receiving a Signed and Encrypted Message
Example C Program: Cosigning and Decoding a Message
Countersigning
Signing Files and Checking Signatures

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/signing-data
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


//   Copyright (C) Microsoft.  All rights reserved.


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//   Define the name of a certificate subject.
//   To use this program, the definition of SIGNER_NAME
//   must be changed to the name of the subject of
//   a certificate that has access to a private key. That certificate
//   must have either the CERT_KEY_PROV_INFO_PROP_ID or 
//   CERT_KEY_CONTEXT_PROP_ID property set for the context to 
//   provide access to the private signature key.

//    You can use a command similar to the following to create a certificate that can be used with this example:
//    makecert -n "cn=Test" -sk Test -ss my


//   Local function prototypes.
bool SignMessage(CRYPT_DATA_BLOB * pSignedMessageBlob);
bool VerifySignedMessage(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pDecodedMessageBlob);


void SigningMessageAndVerifyingMessageSignature(int argc, _TCHAR * argv[])
/*
Example C Program: Signing a Message and Verifying a Message Signature
2018/05/31

The following example implements the procedure described in Procedure for Signing Data.
For general information, see Simplified Messages.
Details about the functions and structures can be found in Base Cryptography Functions,
Simplified Message Functions, and CryptoAPI Structures.

This example also includes code to verify the message signature created.
This code would usually be in a separate program but is included here for completeness and clarity.

This example illustrates the following CryptoAPI functions:

CertOpenStore
CryptSignMessage
CryptVerifyMessageSignature
CertFreeCertificateContext
CertCloseStore
Signing the message can only be done with access to a certificate that has an available private key.
Verification of the message can only be done with access to the public key related to the private key used to sign the certificate.
The user can change the #define statement to the subject name from one of the user's personal certificates.

This example also demonstrates the initialization of the CRYPT_SIGN_MESSAGE_PARA and
CRYPT_VERIFY_MESSAGE_PARA structures needed for calls to CryptSignMessage and CryptVerifyMessageSignature.

This example also uses the function MyHandleError.
Code for this function is included with the example program and also can be seen in General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature
*/
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    CRYPT_DATA_BLOB SignedMessage;

    if (SignMessage(&SignedMessage)) {
        CRYPT_DATA_BLOB DecodedMessage;

        if (VerifySignedMessage(&SignedMessage, &DecodedMessage)) {
            free(DecodedMessage.pbData);
        }

        free(SignedMessage.pbData);
    }

    _tprintf(TEXT("Press any key to exit."));
    (void)_getch();
}


bool SignMessage(CRYPT_DATA_BLOB * pSignedMessageBlob)
{
    bool fReturn = false;
    BYTE * pbMessage;
    DWORD cbMessage;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pSignerCert = NULL;
    CRYPT_SIGN_MESSAGE_PARA  SigParams;
    DWORD cbSignedMessageBlob;
    BYTE * pbSignedMessageBlob = NULL;

    // Initialize the output pointer.
    pSignedMessageBlob->cbData = 0;
    pSignedMessageBlob->pbData = NULL;

    // The message to be signed.
    // Usually, the message exists somewhere and a pointer is passed to the application.
    pbMessage = (BYTE *)TEXT("CryptoAPI is a good way to handle security");

    // Calculate the size of message. To include the 
    // terminating null character, the length is one more byte 
    // than the length returned by the strlen function.
    cbMessage = (lstrlen((TCHAR *)pbMessage) + 1) * sizeof(TCHAR);

    // Create the MessageArray and the MessageSizeArray.
    const BYTE * MessageArray[] = {pbMessage};
    //DWORD_PTR MessageSizeArray[1];
    DWORD MessageSizeArray[1];
    MessageSizeArray[0] = cbMessage;

    //  Begin processing. 
    _tprintf(TEXT("The message to be signed is \"%s\".\n"), pbMessage);

    // Open the certificate store.
    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     0,
                                     NULL,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     CERT_STORE_NAME))) {
        MyHandleError(TEXT("The MY store could not be opened."));
        goto exit_SignMessage;
    }

    // Get a pointer to the signer's certificate.
    // This certificate must have access to the signer's private key.
    if (pSignerCert = CertFindCertificateInStore(hCertStore,
                                                 MY_ENCODING_TYPE,
                                                 0,
                                                 CERT_FIND_SUBJECT_STR,
                                                 SIGNER_NAME,
                                                 NULL)) {
        _tprintf(TEXT("The signer's certificate was found.\n"));
    } else {
        MyHandleError(TEXT("Signer certificate not found."));
        goto exit_SignMessage;
    }

    // Initialize the signature structure.
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pSignerCert;
    SigParams.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
    SigParams.HashAlgorithm.Parameters.cbData = NULL;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;

    // First, get the size of the signed BLOB.
    if (CryptSignMessage(&SigParams,
                         FALSE,
                         1,
                         MessageArray,
                         MessageSizeArray,
                         NULL,
                         &cbSignedMessageBlob)) {
        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"), cbSignedMessageBlob);
    } else {
        MyHandleError(TEXT("Getting signed BLOB size failed"));
        goto exit_SignMessage;
    }

    // Allocate memory for the signed BLOB.
    if (!(pbSignedMessageBlob = (BYTE *)malloc(cbSignedMessageBlob))) {
        MyHandleError(TEXT("Memory allocation error while signing."));
        goto exit_SignMessage;
    }

    // Get the signed message BLOB.
    if (CryptSignMessage(&SigParams,
                         FALSE,
                         1,
                         MessageArray,
                         MessageSizeArray,
                         pbSignedMessageBlob,
                         &cbSignedMessageBlob)) {
        _tprintf(TEXT("The message was signed successfully. \n"));
        fReturn = true;// pbSignedMessageBlob now contains the signed BLOB.
    } else {
        MyHandleError(TEXT("Error getting signed BLOB"));
        goto exit_SignMessage;
    }

exit_SignMessage:

    // Clean up and free memory as needed.
    if (pSignerCert) {
        CertFreeCertificateContext(pSignerCert);
    }

    if (hCertStore) {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    // Only free the signed message if a failure occurred.
    if (!fReturn) {
        if (pbSignedMessageBlob) {
            free(pbSignedMessageBlob);
            pbSignedMessageBlob = NULL;
        }
    }

    if (pbSignedMessageBlob) {
        pSignedMessageBlob->cbData = cbSignedMessageBlob;
        pSignedMessageBlob->pbData = pbSignedMessageBlob;
    }

    return fReturn;
}


bool VerifySignedMessage(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pDecodedMessageBlob)
//    Verify the message signature. Usually, this would be done in a separate program. 
{
    bool fReturn = false;
    DWORD cbDecodedMessageBlob;
    BYTE * pbDecodedMessageBlob = NULL;
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

    // Initialize the output.
    pDecodedMessageBlob->cbData = 0;
    pDecodedMessageBlob->pbData = NULL;

    // Initialize the VerifyParams data structure.
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;

    // First, call CryptVerifyMessageSignature to get the length 
    // of the buffer needed to hold the decoded message.
    if (CryptVerifyMessageSignature(&VerifyParams,
                                    0,
                                    pSignedMessageBlob->pbData,
                                    pSignedMessageBlob->cbData,
                                    NULL,
                                    &cbDecodedMessageBlob,
                                    NULL)) {
        _tprintf(TEXT("%d bytes needed for the decoded message.\n"), cbDecodedMessageBlob);
    } else {
        _tprintf(TEXT("Verification message failed. \n"));
        goto exit_VerifySignedMessage;
    }

    //   Allocate memory for the decoded message.
    if (!(pbDecodedMessageBlob = (BYTE *)malloc(cbDecodedMessageBlob))) {
        MyHandleError(TEXT("Memory allocation error allocating decode BLOB."));
        goto exit_VerifySignedMessage;
    }

    // Call CryptVerifyMessageSignature again to verify the signature
    // and, if successful, copy the decoded message into the buffer. 
    // This will validate the signature against the certificate in the local store.
    if (CryptVerifyMessageSignature(&VerifyParams,
                                    0,
                                    pSignedMessageBlob->pbData,
                                    pSignedMessageBlob->cbData,
                                    pbDecodedMessageBlob,
                                    &cbDecodedMessageBlob,
                                    NULL)) {
        _tprintf(TEXT("The verified message is \"%s\".\n"), pbDecodedMessageBlob);
        fReturn = true;
    } else {
        _tprintf(TEXT("Verification message failed. \n"));
    }

exit_VerifySignedMessage:
    // If something failed and the decoded message buffer was allocated, free it.
    if (!fReturn) {
        if (pbDecodedMessageBlob) {
            free(pbDecodedMessageBlob);
            pbDecodedMessageBlob = NULL;
        }
    }

    // If the decoded message buffer is still around, it means the function was successful. 
    // Copy the pointer and size into the output parameter.
    if (pbDecodedMessageBlob) {
        pDecodedMessageBlob->cbData = cbDecodedMessageBlob;
        pDecodedMessageBlob->pbData = pbDecodedMessageBlob;
    }

    return fReturn;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Example C Program: Signing, Encoding, Decoding, and Verifying a Message
2018/05/31

The following example combines signing and encoding a message, and decoding a signed message and verifying the signature.
The two operations would usually be in separate programs.
The encoding example would create the encoded message, save it to a disk file or in some other way send it to another user.
The decoding example would receive the encoded message, decode it, and verify the signature.
The two processes have been combined here to show both procedures working.

Signing and encoding a message does not ensure privacy for that message. Rather it ensures the authenticity of the message.
Because the message is signed with the sender's private key,
when the receiver of the message decrypts the signature with the sender's public key
(available from the certificate that is sent along with the message),
the receiver can be sure that the message was sent by the person or
entity associated with the certificate and that the message was not changed after it was signed.

This example illustrates the following tasks and CryptoAPI functions for encoding a message:

Opening a certificate store using CertOpenStore.
Retrieving a certificate with a specific subject name using CertFindCertificateInStore.
Getting and printing a certificate's subject name using CertGetNameString.
Initializing a CRYPT_SIGN_MESSAGE_PARA structure to be used in a call to CryptSignMessage.
Signing and encoding a message with CryptSignMessage.
This example illustrates the following tasks and CryptoAPI functions for decoding a message and verifying the signature:

Opening a message for decoding with CryptMsgOpenToDecode.
Adding the encoded BLOB to the message to be decoded by using CryptMsgUpdate.
Decoding the message using CryptMsgGetParam.
Opening a certificate store in memory with CertOpenStore using the message received and decoded.
Using CertGetSubjectCertificateFromStore to get the certificate of the message's signer.
Verifying a message's signature using CryptMsgControl.
Freeing memory, closing certificate stores, and freeing certificate context.
For an example of how to perform these similar operations using a stream callback,
see Example C Program: Encoding and Decoding a Message Using a Stream.

This example uses the function MyHandleError. Code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General_Purpose_Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-signing-encoding-decoding-and-verifying-a-message
*/


// Copyright (C) Microsoft.  All rights reserved.
// Example of encoding and decoding a signed message.


//    Declare local functions.
BOOL EncodeMessage(PCRYPT_DATA_BLOB pEncodedData, LPWSTR pwszSignerName);
void DecodeMessage(PCRYPT_DATA_BLOB pEncodedData, LPWSTR pwszSignerName);


void ReportFailure()
{
    switch (GetLastError()) {
    case CRYPT_E_AUTH_ATTR_MISSING:
        printf("Message does not contain an expected attribute.\n");
        break;
    case CRYPT_E_BAD_ENCODE:
        printf("An error encountered encoding or decoding.\n");
        break;
    case CRYPT_E_HASH_VALUE:
        printf("The hash value is not correct.\n");
        break;
    case CRYPT_E_INVALID_MSG_TYPE:
        printf("The message type is not valid.\n");
        break;
    case CRYPT_E_OSS_ERROR:
        printf("OSS error.\n");
        break;
    case CRYPT_E_SIGNER_NOT_FOUND:
        printf("Signer not found.\n");
        break;
    case CRYPT_E_UNEXPECTED_ENCODING:
        printf("Unexpected encoding. \n");
        break;
    case CRYPT_E_UNKNOWN_ALGO:
        printf("Unknown algorithm.\n");
        break;
    case E_OUTOFMEMORY:
        printf("Out of memory.\n");
        break;
    case ERROR_INVALID_HANDLE:
        printf("The handle from verify signature is not valid.function.\n");
        break;
    case ERROR_INVALID_PARAMETER:
        printf("The parameter from verify signature is not valid.\n");
        break;
    case NTE_BAD_FLAGS:
        printf("Bad Flags from verify signature function.\n");
        break;
    case NTE_BAD_HASH:
        printf("Bad Hash from verify signature function.\n");
        break;
    case NTE_BAD_KEY:
        printf("Bad Key from verify signature function.\n");
        break;
    case NTE_BAD_SIGNATURE:
        printf("Bad signature from verify signature function.\n");
        break;
    case NTE_BAD_UID:
        printf("Bad UID from verify signature function.\n");
        break;
    }  // End switch.
}  // End ReportFailure.


void EncodeAndDecodeMessage(LPWSTR pwszSignerName)
{
    CRYPT_DATA_BLOB EncodedBlob;

    if (EncodeMessage(&EncodedBlob, pwszSignerName)) {
        DecodeMessage(&EncodedBlob, pwszSignerName);
    }
}


BOOL EncodeMessage(PCRYPT_DATA_BLOB pEncodedBlob, LPWSTR pwszSignerName)
{
    /*
        Declare and initialize variables. This includes getting a
        pointer to the message content. This sample creates
        the message content and gets a pointer to it. In most
        situations, the content will exist somewhere, and a
        pointer to it will get passed to the application.
    */

    HCERTSTORE hSystemStoreHandle;
    CRYPT_SIGN_MESSAGE_PARA SignMessagePara;

    //   The message to be signed and encoded.
    BYTE * pbContent = (BYTE *)"The quick brown fox jumped over the lazy dog.";

    /*
        The length of the message. This must be one more than the
        value returned by strlen() to include the terminal NULL character.
    */
    DWORD cbContent = lstrlenA((char *)pbContent) + 1;

    //    Arrays to hold the message to be signed and its length.
    const BYTE * rgpbToBeSigned[1];
    DWORD rgcbToBeSigned[1];


    PCCERT_CONTEXT pSignerCert;//    The signer's certificate.    
    char pszNameString[MAX_NAME];//    Buffer to hold the name of the subject of a certificate.    
    DWORD cbData = sizeof(DWORD);//  The following variables are used only in the decoding phase.

    //  Begin processing. Display the original message.
    rgpbToBeSigned[0] = pbContent;
    rgcbToBeSigned[0] = cbContent;

    printf("The original message = \n%s\n\n", rgpbToBeSigned[0]);

    // Open a certificate store.
    if (hSystemStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                           0,
                                           NULL,
                                           CERT_SYSTEM_STORE_CURRENT_USER,
                                           CERTIFICATE_STORE_NAME)) {
        printf("The certificate store is open. \n");
    } else {
        MyHandleError("Error Getting Store Handle");
    }

    /*
        Find a certificate in the store. This certificate will be
        used to sign the message. To sign the message, the
        certificate must have a private key accessible.
    */

    if (pSignerCert = CertFindCertificateInStore(
        hSystemStoreHandle,
        MY_ENCODING_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        pwszSignerName,
        NULL)) {
        //  Get and print the name of the subject of the certificate.
        if (CertGetNameStringA(pSignerCert,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               pszNameString,
                               MAX_NAME) > 1) {
            printf("The message signer is  %s \n", pszNameString);
        } else {
            MyHandleError("Getting the name of the signer failed.\n");
        }
    } else {
        MyHandleError("Signer certificate not found.");
    }

    /*
    Initialize the CRYPT_SIGN_MESSAGE_PARA structure. First, use
    memset to set all members to zero or NULL. Then set the values of
    all members that must be nonzero.
    */

    memset(&SignMessagePara, 0, sizeof(CRYPT_SIGN_MESSAGE_PARA));
    SignMessagePara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SignMessagePara.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD2;
    SignMessagePara.pSigningCert = pSignerCert;
    SignMessagePara.dwMsgEncodingType = MY_ENCODING_TYPE;
    SignMessagePara.cMsgCert = 1;
    SignMessagePara.rgpMsgCert = &pSignerCert;

    /*
        In two steps, sign and encode the message. First, get the
        number of bytes required for the buffer to hold the signed and encoded message.
    */

    if (CryptSignMessage(&SignMessagePara,
                         FALSE,
                         1,
                         rgpbToBeSigned,
                         rgcbToBeSigned,
                         NULL,
                         &pEncodedBlob->cbData)) {
        printf("The needed length is %d \n", pEncodedBlob->cbData);
    } else {
        MyHandleError("Getting the length failed.\n");
    }

    //   Allocate memory for the required buffer.
    pEncodedBlob->pbData = (BYTE *)malloc(pEncodedBlob->cbData);
    if (!pEncodedBlob->pbData) {
        MyHandleError("Memory allocation failed.");
    }

    //   Call CryptSignMessage a second time to copy the signed and encoded message to the buffer.
    if (CryptSignMessage(&SignMessagePara,
                         FALSE,
                         1,
                         rgpbToBeSigned,
                         rgcbToBeSigned,
                         pEncodedBlob->pbData,
                         &pEncodedBlob->cbData)) {
        printf("Signing worked \n");
    } else {
        MyHandleError("Signing failed.\n");
    }

    //  Clean up after signing and encoding.

    if (pSignerCert) {
        CertFreeCertificateContext(pSignerCert);
    }

    if (hSystemStoreHandle) {
        CertCloseStore(hSystemStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    }

    return TRUE;
}


void DecodeMessage(PCRYPT_DATA_BLOB pEncodedBlob, LPWSTR pwszSignerName)
{
    //    Buffer to hold the name of the subject of a certificate.
    char pszNameString[MAX_NAME];

    //  The following variables are used only in the decoding phase.
    HCRYPTMSG hMsg;
    HCERTSTORE hStoreHandle;           // certificate store handle
    DWORD cbData = sizeof(DWORD);
    DWORD cbDecoded;
    BYTE * pbDecoded;
    DWORD cbSignerCertInfo;
    PCERT_INFO pSignerCertInfo;
    PCCERT_CONTEXT pSignerCertContext;

    /*
        The following code decodes the message and verifies the
        message signature.  This code would normally be in a
        stand-alone program that would read the signed and encoded
        message and its length from a file from an email message,
        or from some other source.
    */

    //  Open a message for decoding.
    if (hMsg = CryptMsgOpenToDecode(
        MY_ENCODING_TYPE,      // encoding type
        0,                     // flags
        0,                     // use the default message type
                               // the message type is listed in the message header
        NULL,                  // cryptographic provider use NULL for the default provider
        NULL,                  // recipient information
        NULL))                 // stream information
    {
        printf("The message to decode is open. \n");
    } else {
        MyHandleError("OpenToDecode failed");
    }

    //  Update the message with an encoded BLOB.
    if (CryptMsgUpdate(
        hMsg,                 // handle to the message
        pEncodedBlob->pbData, // pointer to the encoded BLOB
        pEncodedBlob->cbData, // size of the encoded BLOB
        TRUE))                // last call
    {
        printf("The encoded BLOB has been added to the message. \n");
    } else {
        MyHandleError("Decode MsgUpdate failed");
    }

    //  Get the number of bytes needed for a buffer to hold the decoded message.
    if (CryptMsgGetParam(
        hMsg,                  // handle to the message
        CMSG_CONTENT_PARAM,    // parameter type
        0,                     // index
        NULL,
        &cbDecoded))           // size of the returned information
    {
        printf("The message parameter has been acquired. \n");
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM failed.");
    }

    // Allocate memory.
    if (!(pbDecoded = (BYTE *)malloc(cbDecoded))) {
        MyHandleError("Decode memory allocation failed.");
    }

    // Copy the content to the buffer.
    if (CryptMsgGetParam(
        hMsg,                 // handle to the message
        CMSG_CONTENT_PARAM,   // parameter type
        0,                    // index
        pbDecoded,            // address for returned information
        &cbDecoded))          // size of the returned information
    {
        printf("The decoded message is =>\n%s\n\n", (LPSTR)pbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM #2 failed");
    }

    // Verify the signature.
    // First, get the signer CERT_INFO from the message.

    // Get the size of memory required for the certificate.
    if (CryptMsgGetParam(
        hMsg,                         // handle to the message
        CMSG_SIGNER_CERT_INFO_PARAM,  // parameter type
        0,                            // index
        NULL,
        &cbSignerCertInfo))           // size of the returned information
    {
        printf("%d bytes needed for the buffer.\n", cbSignerCertInfo);
    } else {
        MyHandleError("Verify SIGNER_CERT_INFO #1 failed.");
    }

    // Allocate memory.
    if (!(pSignerCertInfo = (PCERT_INFO)malloc(cbSignerCertInfo))) {
        MyHandleError("Verify memory allocation failed.");
    }

    // Get the message certificate information (CERT_INFO structure).
    if (!(CryptMsgGetParam(
        hMsg,                         // handle to the message
        CMSG_SIGNER_CERT_INFO_PARAM,  // parameter type
        0,                            // index
        pSignerCertInfo,              // address for returned information
        &cbSignerCertInfo)))          // size of the returned information
    {
        MyHandleError("Verify SIGNER_CERT_INFO #2 failed");
    }

    // Open a certificate store in memory using CERT_STORE_PROV_MSG,
    // which initializes it with the certificates from the message.
    if (hStoreHandle = CertOpenStore(
        CERT_STORE_PROV_MSG,         // store provider type 
        MY_ENCODING_TYPE,            // encoding type
        NULL,                        // cryptographic provider
                                     // use NULL for the default
        0,                           // flags
        hMsg))                       // handle to the message
    {
        printf("The certificate store to be used for message verification has been opened.\n");
    } else {
        MyHandleError("Verify open store failed");
    }

    // Find the signer's certificate in the store.
    if (pSignerCertContext = CertGetSubjectCertificateFromStore(
        hStoreHandle,       // handle to the store
        MY_ENCODING_TYPE,   // encoding type
        pSignerCertInfo))   // pointer to retrieved CERT_CONTEXT
    {
        if (CertGetNameStringA(pSignerCertContext,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               pszNameString,
                               MAX_NAME) > 1) {
            printf("The message signer is  %s \n", pszNameString);
        } else {
            MyHandleError("Getting the signer's name failed.\n");
        }
    } else {
        MyHandleError("Verify GetSubjectCert failed");
    }

    // Use the CERT_INFO from the signer certificate to verify the signature.
    if (CryptMsgControl(hMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, pSignerCertContext->pCertInfo)) {
        printf("Verify signature succeeded. \n");
    } else {
        printf("The signature was not verified. \n");
        ReportFailure();
    }

    // Clean up.
    if (pEncodedBlob->pbData) {
        free(pEncodedBlob->pbData);
        pEncodedBlob->pbData = NULL;
    }
    if (pbDecoded) {
        free(pbDecoded);
    }
    if (pSignerCertInfo) {
        free(pSignerCertInfo);
    }
    if (pSignerCertContext) {
        CertFreeCertificateContext(pSignerCertContext);
    }
    if (hStoreHandle) {
        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    }
    if (hMsg) {
        CryptMsgClose(hMsg);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
Example C Program: Encoding and Decoding a Message Using a Stream
2018/05/31

The following example demonstrates how to use the CryptMsgOpenToEncode, CryptMsgOpenToDecode,
and CryptMsgUpdate functions with the CMSG_STREAM_INFO structure to encode and
decode a message using the streaming features of these functions.

Signing and encoding a message does not ensure privacy for that message.
Rather it ensures the authenticity of the message.
Because the message is signed with the sender's private key,
when the receiver of the message decrypts the signature with the sender's public key
(available from the certificate that is sent along with the message),
the receiver can be sure that the message was sent by the person or
entity associated with the certificate and that the message was not changed after it was signed.

This encoding signing portion of this example illustrates the following tasks and CryptoAPI functions:

Opening a certificate store by using CertOpenStore.
Retrieving a certificate with a specific subject name by using CertFindCertificateInStore.
Getting and printing a certificate's subject name by using CertGetNameString.
Getting the handle to a cryptographic provider that can provide a private key with the CryptAcquireCertificatePrivateKey function.
Initializing the CMSG_SIGNED_ENCODE_INFO and CMSG_STREAM_INFO structures to be used in a call to CryptMsgOpenToEncode.
Signing and encoding a message by using CryptMsgOpenToEncode and CryptMsgUpdate.
Implementing a stream callback function that can save an encoded and signed message in any persistent format, such as writing it to a file.
The decoding portion of this example illustrates the following tasks and CryptoAPI functions:

Initializing a CMSG_STREAM_INFO structure to be used in a call to CryptMsgOpenToDecode.
Implementing a stream callback function that can save a decoded message in any persistent format, such as printing it to the screen.
Reading an encoded message from a file and decoding the message by using CryptMsgUpdate.
For an example of how to perform these same operations without using a stream callback,
see Example C Program: Signing, Encoding, Decoding, and Verifying a Message.

This example uses the function MyHandleError. Code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General_Purpose_Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program--encoding-and-decoding-a-message-using-a-stream
*/


BOOL WINAPI EncodeCallback(const void * pvArg, BYTE * pbData, DWORD cbData, BOOL fFinal)
// Callback function used for streamed Signing. 
{
    DWORD dwWrittenBytes = 0;
    HANDLE hFileToWrite = INVALID_HANDLE_VALUE;

    hFileToWrite = *((HANDLE *)pvArg);
    if (!WriteFile(hFileToWrite, pbData, cbData, &dwWrittenBytes, NULL) ||
        (dwWrittenBytes != cbData)) {
        return FALSE;
    }

    return TRUE;
}


BOOL WINAPI DecodeCallback(const void * pvArg, BYTE * pbData, DWORD cbData, BOOL fFinal)
// Callback function used for decoding streamed Signing.
{
    if (pbData != NULL && cbData > 0) {
        *(pbData + cbData) = 0;
        printf("%s", (char *)pbData);
    }

    return TRUE;
}


void EncodeMessageWithStream(LPWSTR pwszSignerName)
{
    // Declare and initialize variables. This includes declaring and 
    // initializing a pointer to message content to be countersigned 
    // and encoded. Usually, the message content will exist somewhere
    // and a pointer to it is passed to the application. 

    BYTE * pbContent1 = (BYTE *)"First sentence. ";
    DWORD cbContent1 = lstrlenA((char *)pbContent1);
    BYTE * pbContent2 = (BYTE *)"Second sentence. ";
    DWORD cbContent2 = lstrlenA((char *)pbContent2);

    HCRYPTPROV hCryptProv;         // CSP handle
    HCERTSTORE hStoreHandle;       // store handle
    PCCERT_CONTEXT pSignerCert;    // signer certificate
    CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo;
    CMSG_SIGNER_ENCODE_INFO SignerEncodeInfoArray[1];
    CERT_BLOB SignerCertBlob;
    CERT_BLOB SignerCertBlobArray[1];
    CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo;
    HCRYPTMSG hMsg;
    LPWSTR pszNameString = NULL;
    DWORD dwKeySpec;

    // Open the My system certificate store.
    if (!(hStoreHandle = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,// The system store will be a virtual store.        
        0,// Encoding type not needed with this PROV.        
        NULL,// Accept the default HCRYPTPROV. 
        CERT_SYSTEM_STORE_CURRENT_USER,
        // Set the system store location in the registry. Other 
        // predefined system stores could have been used, including trust, Ca, or root.
        L"MY"))) {
        MyHandleError(L"Could not open the MY system store.");
    }

    // Get a pointer to a signer's signature certificate.
    if (pSignerCert = CertFindCertificateInStore(hStoreHandle,
                                                 MY_ENCODING_TYPE,
                                                 0,
                                                 CERT_FIND_SUBJECT_STR,
                                                 pwszSignerName,
                                                 NULL)) {
        //   A certificate was found. Get and print the name of the subject of the certificate.
        if (CertGetNameString(pSignerCert,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              0,
                              NULL,
                              pszNameString,
                              MAX_NAME) > 1) {
            printf("The message signer is  %ls \n", pszNameString);
        } else {
            MyHandleError(L"CertGetNameString failed.\n");
        }
    } else {
        MyHandleError(L"Cert not found.\n");
    }

    // Initialize the CMSG_SIGNER_ENCODE_INFO structure.

    // Get a handle to a cryptographic provider. 
    if (!(CryptAcquireCertificatePrivateKey(pSignerCert, 0, NULL, &hCryptProv, &dwKeySpec, NULL))) {
        DWORD dwError = GetLastError();
        if (NTE_BAD_PUBLIC_KEY == dwError) {
            printf("NTE_BAD_PUBLIC_KEY\n");
        }

        MyHandleError(L"CryptAcquireContext failed");
    }

    memset(&SignerEncodeInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    SignerEncodeInfo.pCertInfo = pSignerCert->pCertInfo;
    SignerEncodeInfo.hCryptProv = hCryptProv;
    SignerEncodeInfo.dwKeySpec = dwKeySpec;
    SignerEncodeInfo.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5;
    SignerEncodeInfo.pvHashAuxInfo = NULL;

    // Initialize the first element of an array of signers. 
    // Note: Currently, there is only one signer.
    SignerEncodeInfoArray[0] = SignerEncodeInfo;

    // Initialize the CMSG_SIGNED_ENCODE_INFO structure.
    SignerCertBlob.cbData = pSignerCert->cbCertEncoded;
    SignerCertBlob.pbData = pSignerCert->pbCertEncoded;

    //  Initialize the first element of an array of signer BLOBs.
    //  Note: In this program, there is only one signer BLOB used.
    SignerCertBlobArray[0] = SignerCertBlob;
    memset(&SignedMsgEncodeInfo, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
    SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
    SignedMsgEncodeInfo.cSigners = 1;
    SignedMsgEncodeInfo.rgSigners = SignerEncodeInfoArray;
    SignedMsgEncodeInfo.cCertEncoded = 1;
    SignedMsgEncodeInfo.rgCertEncoded = SignerCertBlobArray;

    // Fill the CMSG_STREAM_INFO structure.
    CMSG_STREAM_INFO stStreamInfo;

    // BER_ENCODING
    stStreamInfo.cbContent = 0xffffffff;
    // DER_ENCODING 
    // stStreamInfo.cbContent = cbContent;

    stStreamInfo.pfnStreamOutput = EncodeCallback;
    HANDLE hOutMsgFile = INVALID_HANDLE_VALUE;
    hOutMsgFile = CreateFile(ENCODED_FILE_NAME,
                             GENERIC_WRITE,
                             FILE_SHARE_WRITE,
                             NULL,
                             CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
    if (INVALID_HANDLE_VALUE == hOutMsgFile) {
        MyHandleError(L"CreateFile (OUT MSG)");
    }

    stStreamInfo.pvArg = &hOutMsgFile;

    // Open a message to encode.
    if (!(hMsg = CryptMsgOpenToEncode(
        MY_ENCODING_TYPE,      // encoding type
        0,                     // flags
        CMSG_SIGNED,           // message type
        &SignedMsgEncodeInfo,  // pointer to structure
        NULL,                  // inner content OID
        &stStreamInfo)))       // stream information
    {
        MyHandleError(L"OpenToEncode failed");
    }

    // Update the message with the data.
    if (!(CryptMsgUpdate(
        hMsg,        // handle to the message
        pbContent1,  // pointer to the content
        cbContent1,  // size of the content
        FALSE)))     // first call
    {
        MyHandleError(L"MsgUpdate failed");
    }

    if (!(CryptMsgUpdate(
        hMsg,        // handle to the message
        pbContent2,  // pointer to the content
        cbContent2,  // size of the content
        TRUE)))      // last call
    {
        MyHandleError(L"MsgUpdate failed");
    }

    // The message is signed and encoded.
    // Close the message handle and the certificate store.
    CryptMsgClose(hMsg);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    CryptReleaseContext(hCryptProv, 0);
    CloseHandle(hOutMsgFile);
}


void DecodeMessageWithStream()
{
    HCRYPTMSG hMsg;// Open the message for decoding.    
    CMSG_STREAM_INFO stStreamInfo2;// Fill the CMSG_STREAM_INFO structure.

    // BER_ENCODING
    stStreamInfo2.cbContent = 0xffffffff;
    stStreamInfo2.pfnStreamOutput = DecodeCallback;

    if (!(hMsg = CryptMsgOpenToDecode(
        MY_ENCODING_TYPE,   // encoding type
        0,                  // flags
        0,                  // message type (get from message)
        NULL,               // cryptographic provider use NULL for the default provider
        NULL,               // recipient information
        &stStreamInfo2)))   // stream information
    {
        MyHandleError(L"OpenToDecode failed.");
    }

    HANDLE hInMsgFile = INVALID_HANDLE_VALUE;
    hInMsgFile = CreateFile(ENCODED_FILE_NAME,
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (INVALID_HANDLE_VALUE == hInMsgFile) {
        MyHandleError(L"CreateFile (IN MSG)");
    }

    const DWORD cbBytesToRead = 256;
    BYTE pbEncodedBlob[cbBytesToRead];
    DWORD cbBytesRead;
    BOOL lastCall = FALSE;

    while (ReadFile(hInMsgFile, pbEncodedBlob, cbBytesToRead, &cbBytesRead, NULL)) {
        if (cbBytesRead < cbBytesToRead) {
            lastCall = TRUE;
        }

        if (!(CryptMsgUpdate(
            hMsg,            // handle to the message
            pbEncodedBlob,   // pointer to the encoded BLOB
            cbBytesRead,     // size of the encoded BLOB
            lastCall)))      // last call
        {
            MyHandleError(L"Decode MsgUpdate failed.");
        }

        if (lastCall) {
            break;
        }
    }

    CryptMsgClose(hMsg);
    CloseHandle(hInMsgFile);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Example C Program: 
// Signs a message by using a sender's private key and encrypts the
// signed message by using a receiver's public key.


#ifdef MAX_NAME
#undef MAX_NAME
#define MAX_NAME 128
#endif


// Copyright (C) Microsoft.  All rights reserved.
// SIGNER_NAME is used with the CertFindCertificateInStore  
// function to retrieve the certificate of the message signer.
// Replace the Unicode string below with the certificate subject 
// name of the message signer.

#ifdef SIGNER_NAME
#undef SIGNER_NAME
#define SIGNER_NAME L"DUMMY_SIGNER_NAME"
#endif


// The local function ShowBytes is declared here and defined after main.
void ShowBytes(BYTE * s, DWORD len);

// Declare local functions SignAndEncrypt, DecryptAndVerify, and WriteSignedAndEncryptedBlob.
// These functions are defined after main.

BYTE * SignAndEncrypt(const BYTE * pbToBeSignedAndEncrypted,
                      DWORD          cbToBeSignedAndEncrypted,
                      DWORD * pcbSignedAndEncryptedBlob);

BYTE * DecryptAndVerify(BYTE * pbSignedAndEncryptedBlob, DWORD  cbSignedAndEncryptedBlob);

void WriteSignedAndEncryptedBlob(DWORD  cbBlob, BYTE * pbBlob);


void SendingAndReceivingSignedAndEncryptedMessage(void)
/*
Example C Program: Sending and Receiving a Signed and Encrypted Message
2018/05/31

The following example signs a message using a sender's private key and encrypts the signed message using a receiver's public key.
The example then decrypts the message using the receiver's private key and verifies the signature using the sender's public key.
The sender's certificate containing the needed public key is included in the encrypted message.
This example also writes the signed and encrypted message to a file.
For more information, see Example C Program: Receiving a Signed and Encrypted Message.

To sign the message, the signer's private key and the signer's certificate must be available.
To encrypt the signed message, a receiver's certificate including the receiver's public key must be available.

To decrypt the message, the receiver's private key must be available.
After the message is decrypted, the signature is verified using the public key from the certificate included in the encrypted message.

 ±¸×¢

Not all of the certificates in a certificate store provide access to the private key associated with that certificate.
When the message is signed and encrypted, a certificate belonging to the signer with access to the private key of that signer must be used.
In addition, the receiver of the message must have access to the private key associated with the public key used to encrypt the message.

This example illustrates the following tasks:

Opening and closing system certificate stores.
Finding certificates for a message sender and message receiver in the open certificate stores.
Finding and printing the subject name from certificates.
Initializing data structures needed to sign, encrypt, decrypt, and verify a message.
Calling a CryptoAPI function to find the required size of a buffer, allocating the buffer of the required size,
and calling the CryptoAPI function again to fill the buffer.
For more information, see Retrieving Data of Unknown Length.
Displaying some of the encrypted contents of a buffer.
The included local function, ShowBytes, displays characters in the buffer with values between '0' and 'z'.
All other characters are displayed as the '-' character.
This example uses the following CryptoAPI functions:

CertOpenStore
CertFindCertificateInStore
CertGetNameString
CryptAcquireCertificatePrivateKey
CryptSignAndEncryptMessage
CryptDecryptAndVerifyMessageSignature
CertFreeCertificateContext
CertCloseStore
This example uses separate functions to show the signing/encryption process and the decryption/signature-verification process.
It also uses MyHandleError to exit the program gracefully in case of any failure.
The code MyHandleError is included with the example and can also be found along with other auxiliary functions under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-sending-and-receiving-a-signed-and-encrypted-message
*/
{
    // Declare and initialize local variables.

    //  pbToBeSignedAndEncrypted is the message to be encrypted and signed.

    const BYTE * pbToBeSignedAndEncrypted =
        (const unsigned char *)"Insert the message to be signed here";

    // This is the length of the message to be
    // encrypted and signed. Note that it is one
    // more that the length returned by strlen()
    // to include the terminating null character.

    DWORD cbToBeSignedAndEncrypted = lstrlenA((const char *)pbToBeSignedAndEncrypted) + 1;

    // Pointer to a buffer that will hold the encrypted and signed message.
    BYTE * pbSignedAndEncryptedBlob;

    // A DWORD to hold the length of the signed and encrypted message.
    DWORD cbSignedAndEncryptedBlob;
    BYTE * pReturnMessage;

    // Call the local function SignAndEncrypt.
    // This function returns a pointer to the 
    // signed and encrypted BLOB and also returns the length of that BLOB.
    pbSignedAndEncryptedBlob = SignAndEncrypt(
        pbToBeSignedAndEncrypted,
        cbToBeSignedAndEncrypted,
        &cbSignedAndEncryptedBlob);

    _tprintf(TEXT("The following is the signed and encrypted ")
             TEXT("message.\n"));
    ShowBytes(pbSignedAndEncryptedBlob, cbSignedAndEncryptedBlob / 4);

    // Open a file and write the signed and encrypted message to the file.
    WriteSignedAndEncryptedBlob(cbSignedAndEncryptedBlob, pbSignedAndEncryptedBlob);

    // Call the local function DecryptAndVerify.
    // This function decrypts and displays the 
    // encrypted message and also verifies the message's signature.

    if (pReturnMessage = DecryptAndVerify(pbSignedAndEncryptedBlob, cbSignedAndEncryptedBlob)) {
        _tprintf(TEXT(" The returned, verified message is ->\n%s\n"), pReturnMessage);
        _tprintf(TEXT(" The program executed without error.\n"));
    } else {
        _tprintf(TEXT("Verification failed.\n"));
    }
}


BYTE * SignAndEncrypt(const BYTE * pbToBeSignedAndEncrypted,
                      DWORD cbToBeSignedAndEncrypted,
                      DWORD * pcbSignedAndEncryptedBlob
)
// Begin definition of the SignAndEncrypt function.
{
    // Declare and initialize local variables.
    FILE * hToSave;
    HCERTSTORE hCertStore;

    // pSignerCertContext will be the certificate of the message signer.
    PCCERT_CONTEXT pSignerCertContext;

    // pReceiverCertContext will be the certificate of the message receiver.
    PCCERT_CONTEXT pReceiverCertContext;

    TCHAR pszNameString[256];
    CRYPT_SIGN_MESSAGE_PARA SignPara;
    CRYPT_ENCRYPT_MESSAGE_PARA EncryptPara;
    DWORD cRecipientCert;
    PCCERT_CONTEXT rgpRecipientCert[5];
    BYTE * pbSignedAndEncryptedBlob = NULL;
    CERT_NAME_BLOB Subject_Blob;
    BYTE * pbDataIn;
    DWORD dwKeySpec;
    HCRYPTPROV hCryptProv;

    // Open the MY certificate store. 
    // For more information, see the CertOpenStore function 
    // PSDK reference page. 
    // Note: Case is not significant in certificate store names.
    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     0,
                                     NULL,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"my"))) {
        MyHandleError(TEXT("The MY store could not be opened."));
    }

    // Get the certificate for the signer.
    if (!(pSignerCertContext = CertFindCertificateInStore(hCertStore,
                                                          MY_ENCODING_TYPE,
                                                          0,
                                                          CERT_FIND_SUBJECT_STR,
                                                          SIGNER_NAME,
                                                          NULL))) {
        MyHandleError(TEXT("Cert not found.\n"));
    }

    // Get and print the name of the message signer.
    // The following two calls to CertGetNameString with different
    // values for the second parameter get two different forms of the certificate subject's name.
    if (CertGetNameString(pSignerCertContext,
                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
                          0,
                          NULL,
                          pszNameString,
                          MAX_NAME) > 1) {
        _tprintf(TEXT("The SIMPLE_DISPLAY_TYPE message signer's name is ")
                 TEXT("%s \n"), pszNameString);
    } else {
        MyHandleError(TEXT("Getting the name of the signer failed.\n"));
    }

    if (CertGetNameString(pSignerCertContext, CERT_NAME_RDN_TYPE, 0, NULL, pszNameString, MAX_NAME) > 1) {
        _tprintf(TEXT("The RDM_TYPE message signer's name is %s \n"), pszNameString);
    } else {
        MyHandleError(TEXT("Getting the name of the signer failed.\n"));
    }

    if (!(CryptAcquireCertificatePrivateKey(pSignerCertContext, 0, NULL, &hCryptProv, &dwKeySpec, NULL))) {
        MyHandleError(TEXT("CryptAcquireCertificatePrivateKey.\n"));
    }

    // Get the certificate for the receiver. In this case,  
    // a BLOB with the name of the receiver is saved in a file.

    // Note: To decrypt the message signed and encrypted here,
    // this program must use the certificate of the intended receiver.
    // The signed and encrypted message can only be
    // decrypted and verified by the owner of the recipient certificate.
    // That user must have access to the private key
    // associated with the public key of the recipient's certificate.

    // To run this sample, the file contains information that allows 
    // the program to find one of the current user's certificates. 
    // The current user should have access to the private key of the
    // certificate and thus can test the verification and decryption. 

    // In normal use, the file would contain information used to find
    // the certificate of an intended receiver of the message. 
    // The signed and encrypted message would be written
    // to a file or otherwise sent to the intended receiver.

    // Open a file and read in the receiver name BLOB.
    if (!(hToSave = fopen("s.txt", "rb"))) {
        MyHandleError(TEXT("Source file was not opened.\n"));
    }

    fread(&(Subject_Blob.cbData), sizeof(DWORD), 1, hToSave);

    if (ferror(hToSave)) {
        MyHandleError(TEXT("The size of the BLOB was not read.\n"));
    }

    if (!(pbDataIn = (BYTE *)malloc(Subject_Blob.cbData))) {
        MyHandleError(TEXT("Memory allocation error."));
    }

    fread(pbDataIn, Subject_Blob.cbData, 1, hToSave);

    if (ferror(hToSave)) {
        MyHandleError(TEXT("BLOB not read."));
    }

    fclose(hToSave);

    Subject_Blob.pbData = pbDataIn;

    // Use the BLOB just read in from the file to find its associated
    // certificate in the MY store.
    // This call to CertFindCertificateInStore uses the CERT_FIND_SUBJECT_NAME dwFindType.

    if (!(pReceiverCertContext = CertFindCertificateInStore(hCertStore,
                                                            MY_ENCODING_TYPE,
                                                            0,
                                                            CERT_FIND_SUBJECT_NAME,
                                                            &Subject_Blob,
                                                            NULL))) {
        MyHandleError(TEXT("Receiver certificate not found."));
    }

    // Get and print the subject name from the receiver's certificate.
    if (CertGetNameString(pReceiverCertContext,
                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
                          0,
                          NULL,
                          pszNameString,
                          MAX_NAME) > 1) {
        _tprintf(TEXT("The message receiver is  %s \n"), pszNameString);
    } else {
        MyHandleError(TEXT("Getting the name of the receiver failed.\n"));
    }

    // Initialize variables and data structures
    // for the call to CryptSignAndEncryptMessage.

    SignPara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SignPara.dwMsgEncodingType = MY_ENCODING_TYPE;
    SignPara.pSigningCert = pSignerCertContext;
    SignPara.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD2;
    SignPara.HashAlgorithm.Parameters.cbData = 0;
    SignPara.pvHashAuxInfo = NULL;
    SignPara.cMsgCert = 1;
    SignPara.rgpMsgCert = &pSignerCertContext;
    SignPara.cMsgCrl = 0;
    SignPara.rgpMsgCrl = NULL;
    SignPara.cAuthAttr = 0;
    SignPara.rgAuthAttr = NULL;
    SignPara.cUnauthAttr = 0;
    SignPara.rgUnauthAttr = NULL;
    SignPara.dwFlags = 0;
    SignPara.dwInnerContentType = 0;

    EncryptPara.cbSize = sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
    EncryptPara.dwMsgEncodingType = MY_ENCODING_TYPE;
    EncryptPara.hCryptProv = 0;
    EncryptPara.ContentEncryptionAlgorithm.pszObjId = (LPSTR)szOID_RSA_RC4;
    EncryptPara.ContentEncryptionAlgorithm.Parameters.cbData = 0;
    EncryptPara.pvEncryptionAuxInfo = NULL;
    EncryptPara.dwFlags = 0;
    EncryptPara.dwInnerContentType = 0;

    cRecipientCert = 1;
    rgpRecipientCert[0] = pReceiverCertContext;
    *pcbSignedAndEncryptedBlob = 0;
    pbSignedAndEncryptedBlob = NULL;

    if (CryptSignAndEncryptMessage(&SignPara,
                                   &EncryptPara,
                                   cRecipientCert,
                                   rgpRecipientCert,
                                   pbToBeSignedAndEncrypted,
                                   cbToBeSignedAndEncrypted,
                                   NULL, // the pbSignedAndEncryptedBlob
                                   pcbSignedAndEncryptedBlob)) {
        _tprintf(TEXT("%d bytes for the buffer .\n"), *pcbSignedAndEncryptedBlob);
    } else {
        MyHandleError(TEXT("Getting the buffer length failed."));
    }

    // Allocate memory for the buffer.
    if (!(pbSignedAndEncryptedBlob = (unsigned char *)malloc(*pcbSignedAndEncryptedBlob))) {
        MyHandleError(TEXT("Memory allocation failed."));
    }

    // Call the function a second time to copy the signed and encrypted message into the buffer.
    if (CryptSignAndEncryptMessage(&SignPara,
                                   &EncryptPara,
                                   cRecipientCert,
                                   rgpRecipientCert,
                                   pbToBeSignedAndEncrypted,
                                   cbToBeSignedAndEncrypted,
                                   pbSignedAndEncryptedBlob,
                                   pcbSignedAndEncryptedBlob)) {
        _tprintf(TEXT("The message is signed and encrypted.\n"));
    } else {
        MyHandleError(TEXT("The message failed to sign and encrypt."));
    }

    // Clean up.

    if (pSignerCertContext) {
        CertFreeCertificateContext(pSignerCertContext);
    }

    if (pReceiverCertContext) {
        CertFreeCertificateContext(pReceiverCertContext);
    }

    CertCloseStore(hCertStore, 0);

    return pbSignedAndEncryptedBlob;// Return the signed and encrypted message.
}  // End SignAndEncrypt.


BYTE * DecryptAndVerify(BYTE * pbSignedAndEncryptedBlob, DWORD  cbSignedAndEncryptedBlob)
// Define the DecryptAndVerify function.
{
    // Declare and initialize local variables.
    HCERTSTORE hCertStore;
    CRYPT_DECRYPT_MESSAGE_PARA DecryptPara;
    CRYPT_VERIFY_MESSAGE_PARA VerifyPara;
    DWORD dwSignerIndex = 0;
    BYTE * pbDecrypted;
    DWORD cbDecrypted;

    // Open the certificate store.
    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     0,
                                     NULL,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"my"))) {
        MyHandleError(TEXT("The MY store could not be opened."));
    }

    // Initialize the needed data structures.

    DecryptPara.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    DecryptPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    DecryptPara.cCertStore = 1;
    DecryptPara.rghCertStore = &hCertStore;

    VerifyPara.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyPara.hCryptProv = 0;
    VerifyPara.pfnGetSignerCertificate = NULL;
    VerifyPara.pvGetArg = NULL;
    pbDecrypted = NULL;
    cbDecrypted = 0;

    // Call CryptDecryptAndVerifyMessageSignature a first time
    // to determine the needed size of the buffer to hold the decrypted message.
    if (!(CryptDecryptAndVerifyMessageSignature(&DecryptPara,
                                                &VerifyPara,
                                                dwSignerIndex,
                                                pbSignedAndEncryptedBlob,
                                                cbSignedAndEncryptedBlob,
                                                NULL,           // pbDecrypted
                                                &cbDecrypted,
                                                NULL,
                                                NULL))) {
        MyHandleError(TEXT("Failed getting size."));
    }

    // Allocate memory for the buffer to hold the decrypted message.
    if (!(pbDecrypted = (BYTE *)malloc(cbDecrypted))) {
        MyHandleError(TEXT("Memory allocation failed."));
    }

    if (!(CryptDecryptAndVerifyMessageSignature(&DecryptPara,
                                                &VerifyPara,
                                                dwSignerIndex,
                                                pbSignedAndEncryptedBlob,
                                                cbSignedAndEncryptedBlob,
                                                pbDecrypted,
                                                &cbDecrypted,
                                                NULL,
                                                NULL))) {
        pbDecrypted = NULL;
    }

    CertCloseStore(hCertStore, 0); // Close the certificate store. 
    return pbDecrypted;// Return the decrypted string or NULL.
} // End of DecryptandVerify.


void WriteSignedAndEncryptedBlob(DWORD cbBlob, BYTE * pbBlob)
// Define the MyHandleError function.
{
    // Open an output file, write the file, and close the file.
    // This function would be used to save the signed and encrypted 
    // message to a file that would be sent to the intended receiver.
    // Note: The only receiver able to decrypt and verify this
    // message will have access to the private key associated 
    // with the public key from the certificate used when the message was encrypted.

    FILE * hOutputFile;

    if (!(hOutputFile = _tfopen(TEXT("sandvout.txt"), TEXT("wb")))) {
        MyHandleError(TEXT("Output file was not opened.\n"));
    }

    fwrite(&cbBlob, sizeof(DWORD), 1, hOutputFile);

    if (ferror(hOutputFile)) {
        MyHandleError(TEXT("The size of the BLOB was not written.\n"));
    }

    fwrite(pbBlob, cbBlob, 1, hOutputFile);

    if (ferror(hOutputFile)) {
        MyHandleError(TEXT("The bytes of the BLOB were not written.\n"));
    } else {
        _tprintf(TEXT("The BLOB has been written to the file.\n"));
    }

    fclose(hOutputFile);
}  // End of WriteSignedAndEcryptedBlob.


void ShowBytes(BYTE * s, DWORD len)
// Define the ShowBytes function.
// This function displays the contents of a BYTE buffer. Characters
// less than '0' or greater than 'z' are all displayed as '-'.
{
    DWORD TotalChars = 0;
    DWORD ThisLine = 0;

    while (TotalChars < len) {
        if (ThisLine > 70) {
            ThisLine = 0;
            _tprintf(TEXT("\n"));
        }
        if (s[TotalChars] < '0' || s[TotalChars] > 'z') {
            _tprintf(TEXT("-"));
        } else {
            _tprintf(TEXT("%c"), s[TotalChars]);
        }

        TotalChars++;
        ThisLine++;
    }

    _tprintf(TEXT("\n"));
} // End of ShowBytes.


//////////////////////////////////////////////////////////////////////////////////////////////////


// Example C Program: 
// Reads a signed and encrypted message, then decrypts and verifies the message.


#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


BYTE * DecryptAndVerify(DWORD cbBlob, BYTE * pbBlob)
{
    //  Declare and initialize local variables.
    HCERTSTORE hCertStore;
    CRYPT_DECRYPT_MESSAGE_PARA DecryptPara;
    CRYPT_VERIFY_MESSAGE_PARA VerifyPara;
    DWORD dwSignerIndex = 0;
    BYTE * pbDecrypted;
    DWORD cbDecrypted;

    //   Open the certificate store.
    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     0,
                                     NULL,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"my"))) {
        MyHandleError(TEXT("The MY store could not be opened."));
    }

    //   Initialize the needed data structures.

    DecryptPara.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    DecryptPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    DecryptPara.cCertStore = 1;
    DecryptPara.rghCertStore = &hCertStore;

    VerifyPara.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyPara.hCryptProv = 0;
    VerifyPara.pfnGetSignerCertificate = NULL;
    VerifyPara.pvGetArg = NULL;
    pbDecrypted = NULL;
    cbDecrypted = 0;

    //     Call CryptDecryptAndVerifyMessageSignature a first time
    //     to determine the needed size of the buffer to hold the decrypted message. 
    //     Note: The sixth parameter is NULL in this call to 
    //     get the required size of the bytes string to contain the decrypted message.

    if (!(CryptDecryptAndVerifyMessageSignature(&DecryptPara,
                                                &VerifyPara,
                                                dwSignerIndex,
                                                pbBlob,
                                                cbBlob,
                                                NULL,
                                                &cbDecrypted,
                                                NULL,
                                                NULL))) {
        MyHandleError(TEXT("Failed getting size."));
    }

    //    Allocate memory for the buffer to hold the decrypted message.
    if (!(pbDecrypted = (BYTE *)malloc(cbDecrypted))) {
        MyHandleError(TEXT("Memory allocation failed."));
    }

    if (!(CryptDecryptAndVerifyMessageSignature(&DecryptPara,
                                                &VerifyPara,
                                                dwSignerIndex,
                                                pbBlob,
                                                cbBlob,
                                                pbDecrypted,
                                                &cbDecrypted,
                                                NULL,
                                                NULL))) {
        pbDecrypted = NULL;
    }

    CertCloseStore(hCertStore, 0);//  Close the certificate store.    
    return pbDecrypted;//    Return the decrypted string or NULL.
} // End of DecryptandVerify.


BYTE * ReadBlob(DWORD * pcbBlob)
{
    FILE * hInputFile;
    BYTE * pbBlob;

    // Open the input file and read in the signed and encrypted BLOB.
    // This file would be created by a program such as the example 
    // program "Example C Program: Sending and Receiving a Signed and 
    // Encrypted Message" in the Platform Software Development Kit (SDK).
    // Change the path name for this file if it is not in the same
    // directory as the executable.

    if (!(hInputFile = _tfopen(TEXT("sandvout.txt"), TEXT("rb")))) {
        MyHandleError(TEXT("Input file was not opened.\n"));
    }

    fread(pcbBlob, sizeof(DWORD), 1, hInputFile);

    if (ferror(hInputFile)) {
        MyHandleError(TEXT("The size of the BLOB was not read.\n"));
    }

    if (!(pbBlob = (BYTE *)malloc(*pcbBlob))) {
        MyHandleError(TEXT("Memory allocation failed."));
    }

    fread(pbBlob, *pcbBlob, 1, hInputFile);

    if (ferror(hInputFile)) {
        MyHandleError(TEXT("The bytes of the BLOB were not read.\n"));
    }

    fclose(hInputFile);

    return pbBlob;
}  // End of ReadBlob.


//   Main calls ReadBlob to read in the signed and encrypted message.
//   It then calls DecryptAndVerify which, if successful, decrypts
//   and verifies the message. 
//   The function main prints the returned, decrypted message
//   if the verification and decryption are successful.

//   Note: The file with the signed and encrypted file must be
//   available, and the user running this program must have access to
//   the private key of the intended message receiver.

//   Also note that this program does not use CryptAcquireContext.
void ReceivingSignedAndEncryptedMessage()
/*
Example C Program: Receiving a Signed and Encrypted Message
2018/05/31

The following example works in conjunction with the program in Example C Program: Sending and Receiving a Signed and Encrypted Message.
It reads the signed and encrypted message, then decrypts and verifies the message.

To decrypt and verify the message, the private key of the message's intended receiver must be available.
The certificate of the signer is included in the message BLOB read in from the file.

This example illustrates the following tasks:

Opening and closing system certificate stores.
Reading a CERT_NAME_BLOB from a file.
Initializing data structures needed to decrypt and verify a message.
Calling a CryptoAPI function to find the required size of a buffer,
allocating the buffer of the required size, and calling the CryptoAPI function again to fill the buffer.
For more information, see Retrieving Data of Unknown Length.
This example uses the following CryptoAPI functions:

CertOpenStore
CryptDecryptAndVerifyMessageSignature
CertCloseStore
This example uses MyHandleError to exit the program gracefully in case of any failure.
The code MyHandleError is included with the sample and can also be found along with other auxiliary functions under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-receiving-a-signed-and-encrypted-message
*/
{
    BYTE * pReturnMessage;
    BYTE * pbBlob;
    DWORD cbBlob;

    if ((pbBlob = ReadBlob(&cbBlob)) == NULL) {
        MyHandleError(TEXT("Read BLOB did not return the BLOB. "));
    }

    if (pReturnMessage = DecryptAndVerify(cbBlob, pbBlob)) {
        _tprintf(TEXT("    The returned, verified message is ->\n%s\n"), pReturnMessage);
        _tprintf(TEXT("    The program executed without error.\n"));
    } else {
        _tprintf(TEXT("Verification failed.\n"));
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.


// Define the name of a certificate subject.
// To use this program, the definitions of SIGNER_NAME and 
// CO_SIGNER_NAME must be changed to the name of the subject of a 
// certificate that has access to a private key. 
// That certificate must have either the CERT_KEY_PROV_INFO_PROP_ID or  
// CERT_KEY_CONTEXT_PROP_ID property set for the context to provide access to the private signature key.


// You can use commands similar to the following to create a 
// certificates that can be used with this example:
//
// makecert -n "cn=test_signer" -sk Test -ss my
// makecert -n "cn=test_co_signer" -sk Test -ss my

//#define SIGNER_NAME L"test_signer"
//#define CO_SIGNER_NAME L"test_co_signer"


// Local function prototypes.
bool SignMessage(CRYPT_DATA_BLOB * pEncodedMessageBlob);
bool CosignMessage(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pCosignedMessageBlob);
bool VerifyCosignedMessage(CRYPT_DATA_BLOB * pEncodedMessageBlob, CRYPT_DATA_BLOB * pDecodedMessageBlob);


int CosigningAndDecodingMessage(int argc, _TCHAR * argv[])
/*
Example C Program: Cosigning and Decoding a Message
2018/05/31

You can use the CryptSignMessage function to cosign a message.
This is accomplished by calling CryptSignMessage once to sign the original message,
and then call CryptSignMessage again to cosign the signed message.

When you verify the signature of a cosigned message,
you use the CryptGetMessageSignerCount function to get the number of signers of the message and
then call the CryptVerifyMessageSignature for each signature.
If all of the signatures are verified, then you know the cosigned message is valid.

The following example shows how to sign a message by more than one person (cosign the message),
verify all signatures, and decode the message.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program--cosigning-and-decoding-a-message
*/
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    CRYPT_DATA_BLOB EncodedMessage;

    if (SignMessage(&EncodedMessage)) {
        CRYPT_DATA_BLOB DecodedMessage;

        if (VerifyCosignedMessage(&EncodedMessage, &DecodedMessage)) {
            free(DecodedMessage.pbData);
        }

        free(EncodedMessage.pbData);
    }

    _tprintf(TEXT("Press any key to exit."));
    (void)_getch();

    return 0;
}


// SignMessage
//bool SignMessage(CRYPT_DATA_BLOB * pEncodedMessageBlob)
//{
//    bool fReturn = false;
//    BYTE * pbMessage;
//    DWORD cbMessage;
//    HCERTSTORE hCertStore = NULL;
//    PCCERT_CONTEXT pSignerCert = NULL;
//    CRYPT_SIGN_MESSAGE_PARA  SigParams;
//    DWORD cbSignedMessageBlob = 0;
//    BYTE * pbSignedMessageBlob = NULL;
//
//    // Initialize the output pointer.
//    pEncodedMessageBlob->cbData = 0;
//    pEncodedMessageBlob->pbData = NULL;
//
//    // The message to be signed.
//    // Usually, the message exists somewhere and a pointer is
//    // passed to the application.
//    pbMessage =
//        (BYTE *)TEXT("CryptoAPI is a good way to handle security");
//
//    // Calculate the size of message. To include the
//    // terminating null character, the length is one more byte 
//    // than the length returned by the strlen function.
//    cbMessage = (lstrlen((TCHAR *)pbMessage) + 1) * sizeof(TCHAR);
//
//    // Create the MessageArray and the MessageSizeArray.
//    const BYTE * MessageArray[] = {pbMessage};
//    DWORD MessageSizeArray[1];
//    MessageSizeArray[0] = cbMessage;
//
//    //  Begin processing. 
//    _tprintf(TEXT("The message to be signed is \"%s\".\n"),
//             pbMessage);
//
//    // Open the certificate store.
//    if (!(hCertStore = CertOpenStore(
//        CERT_STORE_PROV_SYSTEM,
//        0,
//        NULL,
//        CERT_SYSTEM_STORE_CURRENT_USER,
//        CERT_STORE_NAME))) {
//        MyHandleError(TEXT("The MY store could not be opened."));
//        goto exit_SignMessage;
//    }
//
//    // Get a pointer to the signer's certificate.
//    // This certificate must have access to the signer's private key.
//    if (pSignerCert = CertFindCertificateInStore(
//        hCertStore,
//        MY_ENCODING_TYPE,
//        0,
//        CERT_FIND_SUBJECT_STR,
//        SIGNER_NAME,
//        NULL)) {
//        _tprintf(TEXT("The signer's certificate was found.\n"));
//    } else {
//        MyHandleError(TEXT("Signer certificate not found."));
//        goto exit_SignMessage;
//    }
//
//    // Initialize the signature structure.
//    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
//    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
//    SigParams.pSigningCert = pSignerCert;
//    SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
//    SigParams.HashAlgorithm.Parameters.cbData = NULL;
//    SigParams.cMsgCert = 1;
//    SigParams.rgpMsgCert = &pSignerCert;
//    SigParams.cAuthAttr = 0;
//    SigParams.dwInnerContentType = 0;
//    SigParams.cMsgCrl = 0;
//    SigParams.cUnauthAttr = 0;
//    SigParams.dwFlags = 0;
//    SigParams.pvHashAuxInfo = NULL;
//    SigParams.rgAuthAttr = NULL;
//
//    // First, get the size of the signed BLOB.
//    if (CryptSignMessage(
//        &SigParams,
//        FALSE,
//        1,
//        MessageArray,
//        MessageSizeArray,
//        NULL,
//        &cbSignedMessageBlob)) {
//        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
//                 cbSignedMessageBlob);
//    } else {
//        MyHandleError(TEXT("Getting signed BLOB size failed"));
//        goto exit_SignMessage;
//    }
//
//    // Allocate memory for the signed BLOB.
//    if (!(pbSignedMessageBlob =
//          (BYTE *)malloc(cbSignedMessageBlob))) {
//        MyHandleError(
//            TEXT("Memory allocation error while signing."));
//        goto exit_SignMessage;
//    }
//
//    // Get the signed message BLOB.
//    if (CryptSignMessage(
//        &SigParams,
//        FALSE,
//        1,
//        MessageArray,
//        MessageSizeArray,
//        pbSignedMessageBlob,
//        &cbSignedMessageBlob)) {
//        _tprintf(TEXT("The message was signed successfully. \n"));
//
//        // pbSignedMessageBlob now contains the signed BLOB.
//        fReturn = true;
//    } else {
//        MyHandleError(TEXT("Error getting signed BLOB"));
//        goto exit_SignMessage;
//    }
//
//exit_SignMessage:
//
//    // Clean up and free memory as needed.
//    if (pSignerCert) {
//        CertFreeCertificateContext(pSignerCert);
//        pSignerCert = NULL;
//    }
//
//    if (hCertStore) {
//        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
//        hCertStore = NULL;
//    }
//
//    if (pbSignedMessageBlob && fReturn) {
//        fReturn = false;
//        CRYPT_DATA_BLOB SignedMessageBlob;
//        CRYPT_DATA_BLOB CosignedMessageBlob;
//
//        SignedMessageBlob.cbData = cbSignedMessageBlob;
//        SignedMessageBlob.pbData = pbSignedMessageBlob;
//
//        if (CosignMessage(&SignedMessageBlob, &CosignedMessageBlob)) {
//            pEncodedMessageBlob->cbData = CosignedMessageBlob.cbData;
//            pEncodedMessageBlob->pbData = CosignedMessageBlob.pbData;
//
//            fReturn = true;
//        }
//    }
//
//    if (pbSignedMessageBlob) {
//        free(pbSignedMessageBlob);
//        pbSignedMessageBlob = NULL;
//    }
//
//    return fReturn;
//}


bool CosignMessage(CRYPT_DATA_BLOB * pSignedMessageBlob, CRYPT_DATA_BLOB * pCosignedMessageBlob)
{
    bool fReturn = false;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCosignerCert = NULL;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD cbCosignedMessageBlob = 0;
    BYTE * pbCosignedMessageBlob = NULL;

    // Initialize the output pointer.
    pCosignedMessageBlob->cbData = 0;
    pCosignedMessageBlob->pbData = NULL;

    // Open the certificate store.
    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                     0,
                                     NULL,
                                     CERT_SYSTEM_STORE_CURRENT_USER,
                                     CERT_STORE_NAME))) {
        MyHandleError(TEXT("The MY store could not be opened."));
        goto exit_CosignMessage;
    }

    // Get a pointer to the cosigner's certificate.
    // This certificate must have access to the cosigner's private key.
    if ((pCosignerCert = CertFindCertificateInStore(hCertStore,
                                                    MY_ENCODING_TYPE,
                                                    0,
                                                    CERT_FIND_SUBJECT_STR,
                                                    CO_SIGNER_NAME,
                                                    NULL))) {
        _tprintf(TEXT("The signer's certificate was found.\n"));
    } else {
        MyHandleError(TEXT("Signer certificate not found."));
        goto exit_CosignMessage;
    }

    DWORD dwKeySpec;
    if (!(CryptAcquireCertificatePrivateKey(pCosignerCert,
                                            0,
                                            NULL,
                                            &hCryptProv,
                                            &dwKeySpec,
                                            NULL))) {
        MyHandleError(TEXT("CryptAcquireCertificatePrivateKey failed."));
        goto exit_CosignMessage;
    }

    // Open a message for decoding.
    if (!(hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, 0, 0, NULL, NULL, NULL))) {
        MyHandleError(TEXT("CryptMsgOpenToDecode failed."));
        goto exit_CosignMessage;
    }

    // Update the message with the encoded BLOB.
    if (!(CryptMsgUpdate(hMsg,
                         pSignedMessageBlob->pbData,
                         pSignedMessageBlob->cbData,
                         TRUE))) {
        MyHandleError(TEXT("CryptMsgUpdate failed."));
        goto exit_CosignMessage;
    }

    // Initialize the CMSG_SIGNER_ENCODE_INFO structure for the cosigner.
    CMSG_SIGNER_ENCODE_INFO CosignerInfo;
    memset(&CosignerInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    CosignerInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    CosignerInfo.pCertInfo = pCosignerCert->pCertInfo;
    CosignerInfo.hCryptProv = hCryptProv;
    CosignerInfo.dwKeySpec = dwKeySpec;
    CosignerInfo.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;

    // Add the cosigner to the message.
    if (CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER, &CosignerInfo)) {
        _tprintf(TEXT("CMSG_CTRL_ADD_SIGNER succeeded. \n"));
    } else {
        MyHandleError(TEXT("CMSG_CTRL_ADD_SIGNER failed."));
        goto exit_CosignMessage;
    }

    // Add the cosigner's certificate to the message.
    CERT_BLOB CosignCertBlob;
    CosignCertBlob.cbData = pCosignerCert->cbCertEncoded;
    CosignCertBlob.pbData = pCosignerCert->pbCertEncoded;

    if (CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_CERT, &CosignCertBlob)) {
        _tprintf(TEXT("CMSG_CTRL_ADD_CERT succeeded. \n"));
    } else {
        MyHandleError(TEXT("CMSG_CTRL_ADD_CERT failed."));
        goto exit_CosignMessage;
    }

    // Get the size of the cosigned BLOB.
    if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, NULL, &cbCosignedMessageBlob)) {
        _tprintf(TEXT("The size for the encoded BLOB is %d.\n"), cbCosignedMessageBlob);
    } else {
        MyHandleError(TEXT("Sizing of cbSignerInfo failed."));
        goto exit_CosignMessage;
    }

    // Allocate memory for the cosigned BLOB.
    if (!(pbCosignedMessageBlob = (BYTE *)malloc(cbCosignedMessageBlob))) {
        MyHandleError(TEXT("Memory allocation error while cosigning."));
        goto exit_CosignMessage;
    }

    // Get the cosigned message BLOB.
    if (CryptMsgGetParam(hMsg,
                         CMSG_ENCODED_MESSAGE,
                         0,
                         pbCosignedMessageBlob,
                         &cbCosignedMessageBlob)) {
        _tprintf(TEXT("The message was cosigned successfully. \n"));
        fReturn = true;// pbSignedMessageBlob now contains the signed BLOB.
    } else {
        MyHandleError(TEXT("Sizing of cbSignerInfo failed."));
        goto exit_CosignMessage;
    }

exit_CosignMessage:

    // Clean up and free memory as needed.

    if (hMsg) {
        CryptMsgClose(hMsg);
    }

    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
        hCryptProv = NULL;
    }

    if (pCosignerCert) {
        CertFreeCertificateContext(pCosignerCert);
        pCosignerCert = NULL;
    }

    if (hCertStore) {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    // Only free the cosigned message if a failure occurred.
    if (!fReturn) {
        if (pbCosignedMessageBlob) {
            free(pbCosignedMessageBlob);
            pbCosignedMessageBlob = NULL;
        }
    }

    if (pbCosignedMessageBlob) {
        pCosignedMessageBlob->cbData = cbCosignedMessageBlob;
        pCosignedMessageBlob->pbData = pbCosignedMessageBlob;
    }

    return fReturn;
}


bool VerifyCosignedMessage(CRYPT_DATA_BLOB * pCosignedMessageBlob, CRYPT_DATA_BLOB * pDecodedMessageBlob)
{
    bool fReturn = false;
    BYTE * pbDecodedMessage = NULL;
    DWORD cbDecodedMessage = 0;

    // Get the number of signers of the message.
    LONG lSigners = CryptGetMessageSignerCount(MY_ENCODING_TYPE,
                                               pCosignedMessageBlob->pbData,
                                               pCosignedMessageBlob->cbData);
    if (-1 == lSigners) {
        MyHandleError(TEXT("CryptGetMessageSignerCount failed."));
        goto exit_VerifyCosignedMessage;
    }

    // Loop through all of the signers and verify the signature for each one.
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = NULL;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;

    for (LONG i = 0; i < lSigners; i++) {
        if (!(CryptVerifyMessageSignature(&VerifyParams,
                                          i,
                                          pCosignedMessageBlob->pbData,
                                          pCosignedMessageBlob->cbData,
                                          NULL,
                                          NULL,
                                          NULL))) {
            MyHandleError(TEXT("One of the message signatures ")
                          TEXT("could not be verified."));
            goto exit_VerifyCosignedMessage;
        }
    }

    // At this point, all of the signatures in the message have been 
    // verified. Get the decoded data from the message.
    _tprintf(TEXT("All signatures in the message have been verified.\n"));

    // Get the size of the decoded message
    if (!(CryptVerifyMessageSignature(&VerifyParams,
                                      0,
                                      pCosignedMessageBlob->pbData,
                                      pCosignedMessageBlob->cbData,
                                      NULL,
                                      &cbDecodedMessage,
                                      NULL))) {
        MyHandleError(TEXT("CryptVerifyMessageSignature failed."));
        goto exit_VerifyCosignedMessage;
    }

    // Allocate memory for the decoded message.
    if (!(pbDecodedMessage = (BYTE *)malloc(cbDecodedMessage))) {
        MyHandleError(TEXT("Memory allocation error while decoding."));
        goto exit_VerifyCosignedMessage;
    }

    if ((CryptVerifyMessageSignature(&VerifyParams,
                                     0,
                                     pCosignedMessageBlob->pbData,
                                     pCosignedMessageBlob->cbData,
                                     pbDecodedMessage,
                                     &cbDecodedMessage,
                                     NULL))) {
        fReturn = true;
    } else {
        MyHandleError(TEXT("CryptVerifyMessageSignature failed."));
        goto exit_VerifyCosignedMessage;
    }

    _tprintf(TEXT("The verified message is \"%s\".\n"), pbDecodedMessage);

exit_VerifyCosignedMessage:

    // If an error occurred and memory was allocated, free it.
    if (!fReturn) {
        if (pbDecodedMessage) {
            free(pbDecodedMessage);
            pbDecodedMessage = NULL;
        }
    }

    if (pbDecodedMessage) {
        pDecodedMessageBlob->cbData = cbDecodedMessage;
        pDecodedMessageBlob->pbData = pbDecodedMessage;
    }

    return fReturn;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//   Define the names of two certificate subjects.
//   To use this program, the definitions of SIGNER_NAME and 
//   COUNTER_SIGNER_NAME must be changed to the names of 
//   the subjects of certificates that have access to private keys. 
//   These certificates must have either the 
//   CERT_KEY_PROV_INFO_PROP_ID or CERT_KEY_CONTEXT_PROP_ID 
//   property set for the contexts to provide access to private signature keys.


int EncodingAndDecodingCountersignedMessage(int argc, _TCHAR * argv[])
/*
Example C Program: Encoding and Decoding a Countersigned Message
2018/05/31

The following example shows how to encode and decode a countersigned message.
This example uses the MyHandleError example function. Code for the MyHandleError function and
other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-encoding-and-decoding-a-countersigned-message
*/
{
    // Declare and initialize variables. This includes declaring and 
    // initializing a pointer to message content to be countersigned 
    // and encoded. Usually, the message content will exist somewhere
    // and a pointer to it is passed to the application. 

    BYTE * pbContent;
    DWORD cbContent;
    HCRYPTPROV hCryptProv;
    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pSignerCert;
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
    char pszNameString[MAX_NAME];
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;
    BYTE * pbDecodedMessageBlob;
    DWORD cbDecodedMessageBlob;
    DWORD dwKeySpec;

    // The message.
    pbContent = (BYTE *)"I must go back to where all messages start.";

    // Begin processing. 

    //  Initialize cbContent to the length of pbContent
    //  including the terminating NULL character.
    cbContent = lstrlenA((char *)pbContent) + 1;

    printf("The example message is ->.\n");
    printf("%s\n\n", pbContent);

    // Open the MY system certificate store.
    if (!(hStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                       0,
                                       NULL,
                                       CERT_SYSTEM_STORE_CURRENT_USER,
                                       L"MY"))) {
        MyHandleError("Could not open the MY system store.");
    }

    // Get a pointer to a signer's signature certificate.
    if (pSignerCert = CertFindCertificateInStore(hStoreHandle,
                                                 MY_ENCODING_TYPE,
                                                 0,
                                                 CERT_FIND_SUBJECT_STR,
                                                 SIGNER_NAME,
                                                 NULL)) {
        // A certificate was found. Get and print the name of the subject of the certificate.
        if (CertGetNameStringA(pSignerCert,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               pszNameString,
                               MAX_NAME) > 1) {
            printf("The message signer is %s.\n", pszNameString);
        } else {
            MyHandleError("Getting the signer name failed.\n");
        }
    } else {
        MyHandleError("Cert not found.\n");
    }

    // Initialize the CMSG_SIGNER_ENCODE_INFO structure.

    // Get a handle to a cryptographic provider. 
    if (!(CryptAcquireCertificatePrivateKey(pSignerCert, 0, NULL, &hCryptProv, &dwKeySpec, NULL))) {
        MyHandleError("CryptAcquireContext failed.");
    }

    memset(&SignerEncodeInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    SignerEncodeInfo.pCertInfo = pSignerCert->pCertInfo;
    SignerEncodeInfo.hCryptProv = hCryptProv;
    SignerEncodeInfo.dwKeySpec = dwKeySpec;
    SignerEncodeInfo.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5;
    SignerEncodeInfo.pvHashAuxInfo = NULL;

    // Initialize the first element of an array of signers. 
    // Note: Currently, there is only one signer.
    SignerEncodeInfoArray[0] = SignerEncodeInfo;

    // Initialize the CMSG_SIGNED_ENCODE_INFO structure.
    SignerCertBlob.cbData = pSignerCert->cbCertEncoded;
    SignerCertBlob.pbData = pSignerCert->pbCertEncoded;

    //  Initialize the first element of an array of signer BLOBs.
    //  Note: In this program, only one signer BLOB is used.
    SignerCertBlobArray[0] = SignerCertBlob;
    memset(&SignedMsgEncodeInfo, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
    SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
    SignedMsgEncodeInfo.cSigners = 1;
    SignedMsgEncodeInfo.rgSigners = SignerEncodeInfoArray;
    SignedMsgEncodeInfo.cCertEncoded = 1;
    SignedMsgEncodeInfo.rgCertEncoded = SignerCertBlobArray;

    // Get the size of the encoded message BLOB.
    cbEncodedBlob = CryptMsgCalculateEncodedLength(MY_ENCODING_TYPE,
                                                   0,
                                                   CMSG_SIGNED,
                                                   &SignedMsgEncodeInfo,
                                                   NULL,
                                                   cbContent);
    if (!cbEncodedBlob) {
        MyHandleError("Getting cbEncodedBlob length failed.");
    }

    // Allocate memory for the encoded BLOB.
    pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob);
    if (!pbEncodedBlob) {
        MyHandleError("malloc operation failed.");
    }

    // Open a message to encode.
    hMsg = CryptMsgOpenToEncode(MY_ENCODING_TYPE, 0, CMSG_SIGNED, &SignedMsgEncodeInfo, NULL, NULL);
    if (!hMsg) {
        MyHandleError("OpenToEncode failed.");
    }

    // Update the message with the data.
    if (!(CryptMsgUpdate(hMsg, pbContent, cbContent, TRUE))) {
        MyHandleError("CryptMsgUpdate failed.");
    }

    // Get the resulting message.
    if (CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, pbEncodedBlob, &cbEncodedBlob)) {
        printf("Message successfully signed.\n");
    } else {
        MyHandleError("CryptMsgGetParam failed.");
    }

    // The message is signed and encoded.
    // Close the message handle and the certificate store.
    CryptMsgClose(hMsg);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    CryptReleaseContext(hCryptProv, 0);

    // Next, countersign the signed message. 
    // Assume that pbEncodedBlob, the message just created, was sent to an intended recipient.

    // From the recipient's point of view, the following code 
    // completes these steps: 
    //     1.  Decodes the message
    //     2.  Verifies the signature on the message
    //     3.  Adds a countersignature to the signed message
    //
    // The counter-signed message is returned to the original signer 
    // of the message, where the counter-signature is verified.

    // Open a message for decoding.
    hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, 0, 0, NULL, NULL, NULL);
    if (!hMsg) {
        MyHandleError("CryptOpenToDecode failed.");
    }

    // Update the message with the encoded BLOB.
    if (!(CryptMsgUpdate(hMsg, pbEncodedBlob, cbEncodedBlob, TRUE))) {
        MyHandleError("Decode CryptMsgUpdate failed.");
    }

    // Get the size of the message.
    if (CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, &cbDecoded)) {
        printf("The message is %d bytes long.\n", cbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM failed.");
    }

    // Allocate memory.
    pbDecoded = (BYTE *)malloc(cbDecoded);
    if (!pbDecoded) {
        MyHandleError("Decode memory allocation failed.");
    }

    // Copy the message to the buffer.
    if (CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, pbDecoded, &cbDecoded)) {
        printf("The successfully decoded message is -> ");
        printf("%s\n", pbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM #2 failed.");
    }

    //  Check the signature. 
    //  Initialize the VerifyParams data structure.
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;
    if (!(CryptVerifyMessageSignature(&VerifyParams,
                                      0,
                                      pbEncodedBlob,
                                      cbEncodedBlob,
                                      NULL,
                                      &cbDecodedMessageBlob,
                                      NULL))) {
        printf("Getting the size of the verification message failed.\n");
    }

    pbDecodedMessageBlob = (BYTE *)malloc(cbDecodedMessageBlob);
    if (!pbDecodedMessageBlob) {
        MyHandleError("Memory allocation failed.");
    }

    if (CryptVerifyMessageSignature(&VerifyParams,
                                    0,
                                    pbEncodedBlob,
                                    cbEncodedBlob,
                                    pbDecodedMessageBlob,
                                    &cbDecodedMessageBlob,
                                    NULL)) {
        printf("The Signature verified message is -> \n");
        printf("%s \n\n", pbDecodedMessageBlob);
    } else {
        MyHandleError("Verification message failed.");
    }

    // Proceed with the countersigning.
    // First, open a certificate store.
    if (!(hStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                       0,
                                       NULL,
                                       CERT_SYSTEM_STORE_CURRENT_USER,
                                       L"MY"))) {
        MyHandleError("Could not open the MY system store.");
    }

    // Get the countersigner's certificate. 
    if (pCntrSigCert = CertFindCertificateInStore(hStoreHandle,
                                                  MY_ENCODING_TYPE,
                                                  0,
                                                  CERT_FIND_SUBJECT_STR,
                                                  COUNTER_SIGNER_NAME,
                                                  NULL)) {
        if (CertGetNameStringA(pCntrSigCert,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               pszNameString,
                               MAX_NAME) > 1) {
            printf("The counter signer is %s.\n", pszNameString);
        } else {
            MyHandleError("Getting the countersigner name failed.\n");
        }
    } else {
        MyHandleError("Could not find the countersigner's certificate.");
    }

    // Initialize the CMSG_SIGNER_ENCODE_INFO structure.
    if (!(CryptAcquireCertificatePrivateKey(pCntrSigCert, 0, NULL, &hCryptProv, &dwKeySpec, NULL))) {
        MyHandleError("CryptAcquireContext failed.");
    }

    memset(&CountersignerInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
    CountersignerInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    CountersignerInfo.pCertInfo = pCntrSigCert->pCertInfo;
    CountersignerInfo.hCryptProv = hCryptProv;
    CountersignerInfo.dwKeySpec = dwKeySpec;
    CountersignerInfo.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_MD5;

    CntrSignArray[0] = CountersignerInfo;

    // Countersign the message.
    if (CryptMsgCountersign(hMsg, 0, 1, CntrSignArray)) {
        printf("CryptMsgCountersign succeeded.\n");
    } else {
        MyHandleError("CryptMsgCountersign failed.");
    }

    // Get a pointer to the new, countersigned message BLOB.
    // Get the size of memory required.
    if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, NULL, &cbEncodedBlob)) {
        printf("The size of the encoded BLOB is %d.\n", cbEncodedBlob);
    } else {
        MyHandleError("Sizing of cbSignerInfo failed.");
    }

    // Allocate memory.
    pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob);
    if (pbEncodedBlob) {
        printf("%d bytes allocated.\n", cbEncodedBlob);
    } else {
        MyHandleError("cbSignerInfo memory allocation failed.");
    }

    // Get the new message encoded BLOB.
    if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, pbEncodedBlob, &cbEncodedBlob)) {
        printf("The message is complete. \n");
    } else {
        MyHandleError("Getting pbEncodedBlob failed.");
    }

    CryptMsgClose(hMsg);//  The message is complete. Close the handle.

    // Verify the countersignature.
    // Assume that the countersigned message 
    // went back to the originator, 
    // where, again, it will be decoded.

    // Before verifying the countersignature, the message must first be decoded.

    // Open a message for decoding.
    if (hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, 0, 0, 0, NULL, NULL)) {
        printf("The message to decode has been opened.\n");
    } else {
        MyHandleError("CryptMsgOpenToDecode failed.");
    }

    // Update the message with the encoded BLOB.
    if (CryptMsgUpdate(hMsg, pbEncodedBlob, cbEncodedBlob, TRUE)) {
        printf("The message to decode has been updated.\n");
    } else {
        MyHandleError("Updating the countersignature message failed.");
    }

    // Get a pointer to the CERT_INFO member of countersigner's  certificate. 

    // Retrieve the signer information from the message.
    // Get the size of memory required.
    if (CryptMsgGetParam(hMsg, CMSG_ENCODED_SIGNER, 0, NULL, &cbSignerInfo)) {
        printf("Signer information is %d bytes.\n", cbSignerInfo);
    } else {
        MyHandleError("Sizing of cbSignerInfo failed.");
    }

    // Allocate memory.
    pbSignerInfo = (BYTE *)malloc(cbSignerInfo);
    if (!pbSignerInfo) {
        MyHandleError("cbSignerInfo memory allocation failed.");
    }

    // Get the message signer information.
    if (!(CryptMsgGetParam(hMsg, CMSG_ENCODED_SIGNER, 0, pbSignerInfo, &cbSignerInfo))) {
        MyHandleError("Getting pbSignerInfo failed.");
    }

    // Retrieve the countersigner information from the message.
    // Get the size of memory required.
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &cbCountersignerInfo)) {
        printf("Counter Signer information is %d bytes.\n", cbCountersignerInfo);
    } else {
        MyHandleError("Sizing of cbCountersignerInfo failed.");
    }

    // Allocate memory.
    pCountersignerInfo = (CRYPT_ATTRIBUTES *)malloc(cbCountersignerInfo);
    if (!pCountersignerInfo) {
        MyHandleError("pbCountersignInfo memory allocation failed.");
    }

    // Get the message counter signer info.
    if (!(CryptMsgGetParam(hMsg,
                           CMSG_SIGNER_UNAUTH_ATTR_PARAM,
                           0,
                           pCountersignerInfo,
                           &cbCountersignerInfo))) {
        MyHandleError("Getting pbCountersignerInfo failed.");
    }

    //  Verify the countersignature.
    if (CryptMsgVerifyCountersignatureEncoded(0,
                                              MY_ENCODING_TYPE,
                                              pbSignerInfo,
                                              cbSignerInfo,
                                              pCountersignerInfo->rgAttr->rgValue->pbData,
                                              pCountersignerInfo->rgAttr->rgValue->cbData,
                                              pCntrSigCert->pCertInfo)) {
        printf("Verification of countersignature succeeded.\n");
    } else {
        printf("Verification of countersignature failed.\n");
        if (GetLastError() == NTE_BAD_SIGNATURE) {
            printf("Bad signature.\n");
        } else {
            printf("Other verification error.\n");
        }
    }

    // Clean up.
    free(pbEncodedBlob);
    free(pbDecoded);
    free(pbSignerInfo);
    free(pCountersignerInfo);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
    CryptMsgClose(hMsg);
    CryptReleaseContext(hCryptProv, 0);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// Copyright (C) Microsoft.  All rights reserved.
// Example of encoding and decoding a message.


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


void EncodingAndDecodingData(void)
/*
Example C Program: Encoding and Decoding Data
2018/05/31

The following example encodes and decodes simple, general data,
and illustrates the following tasks and CryptoAPI functions.

Determining the length needed for the buffer to hold the encoded data using CryptMsgCalculateEncodedLength.
Opening a message for encoding using CryptMsgOpenToEncode.
Adding content to the encoded message using CryptMsgUpdate.
Copying the encoded message into a buffer using CryptMsgGetParam.
Closing the encoded message using CryptMsgClose.
Opening a message to decode using CryptMsgOpenToDecode.
Using CryptMsgUpdate and CryptMsgGetParam to get the decoded data.
This example uses the function MyHandleError. The code for this function is included with the sample.
Code for this and other auxiliary functions is also listed under General Purpose Functions.

https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program-encoding-and-decoding-data
*/
{
    // Declare and initialize variables. This includes getting a pointer 
    // to the message content. This sample program creates the message 
    // content and gets a pointer to it. In most situations, 
    // the content will exist somewhere and a pointer to it will get passed to the application. 

    HCRYPTMSG hMsg;
    BYTE * pbContent;     // a byte pointer to the message
    DWORD cbContent;     // the size of message
    DWORD cbEncodedBlob;
    BYTE * pbEncodedBlob;

    //  The following variables are used only in the decoding phase.
    DWORD cbDecoded;
    BYTE * pbDecoded;

    //  Begin processing. Display the original message.
    pbContent = (BYTE *)"Security is our only business";
    cbContent = (DWORD)strlen((char *)pbContent) + 1;

    printf("The original message => %s\n", pbContent);

    // Get the size of the encoded message BLOB.
    if (cbEncodedBlob = CryptMsgCalculateEncodedLength(
        MY_ENCODING_TYPE,       // message encoding type
        0,                      // flags
        CMSG_DATA,              // message type
        NULL,                   // pointer to structure
        NULL,                   // inner content object ID
        cbContent))             // size of content
    {
        printf("The length of the data has been calculated. \n");
    } else {
        MyHandleError("Getting cbEncodedBlob length failed");
    }

    // Allocate memory for the encoded BLOB.
    if (pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob)) {
        printf("Memory has been allocated for the signed message. \n");
    } else {
        MyHandleError("Memory allocation failed");
    }

    // Open a message to encode.
    if (hMsg = CryptMsgOpenToEncode(
        MY_ENCODING_TYPE,        // encoding type
        0,                       // flags
        CMSG_DATA,               // message type
        NULL,                    // pointer to structure
        NULL,                    // inner content object ID
        NULL))                   // stream information (not used)
    {
        printf("The message to be encoded has been opened. \n");
    } else {
        MyHandleError("OpenToEncode failed");
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
        MyHandleError("MsgUpdate failed");
    }

    // Get the resulting message.
    if (CryptMsgGetParam(
        hMsg,                      // handle to the message
        CMSG_BARE_CONTENT_PARAM,   // parameter type
        0,                         // index
        pbEncodedBlob,             // pointer to the BLOB
        &cbEncodedBlob))           // size of the BLOB
    {
        printf("Message encoded successfully. \n");
    } else {
        MyHandleError("MsgGetParam failed");
    }

    // pbEncodedBlob now points to the encoded, signed content.

    // Close the message.
    if (hMsg)
        CryptMsgClose(hMsg);

    // The following code decodes a message. 
    // This code may be included here or could be used
    // in a stand-alone program if the message 
    // to be decoded and its size were input. 
    // The encoded message BLOB and its length could be read 
    // from a disk file or could be extracted from an email message or other input source.

    // Open a message for decoding.
    if (hMsg = CryptMsgOpenToDecode(
        MY_ENCODING_TYPE,      // encoding type.
        0,                     // flags.
        CMSG_DATA,             // look for a data message.
        NULL,                  // cryptographic provider.
        NULL,                  // recipient information.
        NULL))                 // stream information.
    {
        printf("The message to decode is open. \n");
    } else {
        MyHandleError("OpenToDecode failed");
    }

    // Update the message with an encoded BLOB.
    // Both pbEncodedBlob, the encoded data, 
    // and cbEncodedBlob, the length of the encoded data, must be available. 

    printf("\nThe length of the encoded message is %d.\n\n", cbEncodedBlob);

    if (CryptMsgUpdate(
        hMsg,                 // handle to the message
        pbEncodedBlob,        // pointer to the encoded BLOB
        cbEncodedBlob,        // size of the encoded BLOB
        TRUE))                // last call
    {
        printf("The encoded BLOB has been added to the message. \n");
    } else {
        MyHandleError("Decode MsgUpdate failed");
    }

    // Get the size of the content.
    if (CryptMsgGetParam(
        hMsg,                  // handle to the message
        CMSG_CONTENT_PARAM,    // parameter type
        0,                     // index
        NULL,                  // address for returned information
        &cbDecoded))           // size of the returned information
    {
        printf("The decoded message size is %d. \n", cbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM failed");
    }

    // Allocate memory.
    if (pbDecoded = (BYTE *)malloc(cbDecoded)) {
        printf("Memory has been allocated for the decoded message.\n");
    } else {
        MyHandleError("Decoding memory allocation failed.");
    }

    // Get a pointer to the content.
    if (CryptMsgGetParam(
        hMsg,                  // handle to the message
        CMSG_CONTENT_PARAM,    // parameter type
        0,                     // index
        pbDecoded,             // address for returned information
        &cbDecoded))           // size of the returned information
    {
        printf("The message is %s.\n", (LPSTR)pbDecoded);
    } else {
        MyHandleError("Decode CMSG_CONTENT_PARAM #2 failed");
    }

    // Clean up.

    if (pbEncodedBlob)
        free(pbEncodedBlob);
    if (pbDecoded)
        free(pbDecoded);
    if (hMsg)
        CryptMsgClose(hMsg);

    printf("This program ran to completion without error. \n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////
