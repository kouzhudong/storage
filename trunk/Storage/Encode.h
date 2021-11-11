#pragma once

class Encode
{

};


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


// Define the name of the store where the needed certificate can be found. 
#define CERT_STORE_NAME  L"MY"


#ifdef SIGNER_NAME
#undef SIGNER_NAME
#define SIGNER_NAME L"Insert_signer_name_here"
#endif


#define CO_SIGNER_NAME L"Insert_co_signer_name_here"


#ifdef MAX_NAME
#undef MAX_NAME
#define MAX_NAME 256
#endif


#define MAX_NAME 256
#define CERTIFICATE_STORE_NAME L"MY"


#define SIGNER_NAME L"Insert_signer_name_here"
#define COUNTER_SIGNER_NAME L"Insert_counter_signer_name_here"


#define ENCODED_FILE_NAME L"testStream.p7s"
