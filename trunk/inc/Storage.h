#pragma once


/////////////////////////////////////////////////////////////////////////////////////////////////
//一些系统的头文件和库的包含。


//#define _WIN32_WINNT 0x0501

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#ifndef UNICODE
#define UNICODE
#endif

#pragma warning(disable:28251)
#pragma warning(disable:28301)

#include <windows.h>
#include <winioctl.h>

//C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared\fltUserStructures.h
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef int(WINAPI * FileCallBack) (_In_ TCHAR * FullFileName, _In_ PWIN32_FIND_DATA ffd, _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


void WINAPI GetFileHardLinkInformation(IN LPCWSTR FileName);
void WINAPI GetFileReparsePointInformation(IN LPCWSTR FileName);

BOOL WINAPI GetDriveGeometry(LPWSTR wszPath, DISK_GEOMETRY * pdg);
int WINAPI ReadDiskSector(_In_ LPCWSTR lpFileName,
                          _In_ LONGLONG QuadPart,
                          _Out_writes_opt_(nNumberOfBytesToRead) LPVOID lpBuffer,
                          _In_ DWORD nNumberOfBytesToRead);
int WINAPI ReadMBR(_In_ LPCWSTR lpFileName,
                   _Out_writes_opt_(nNumberOfBytesToRead) LPVOID lpBuffer,
                   _In_ DWORD nNumberOfBytesToRead);
int WINAPI GetMft(_In_ LPCWSTR lpFileName);
int WINAPI WriteMBR(_In_ LPCWSTR lpFileName);

void WINAPI TestGetDiskFreeSpaceEx();

int WINAPI CppShellKnownFolders();

void WINAPI GetImageFilePath(_Out_ LPWSTR ImageFilePath, _In_ DWORD nSize);

BOOL WINAPI DelDirByApi(_In_ LPCWSTR Dir);
void WINAPI DelDirByShell(_In_ LPCWSTR Dir);

void WINAPI GetSpecialFolderPath();


//////////////////////////////////////////////////////////////////////////////////////////////////
//签名和验签


LONG WINAPI VerifyEmbeddedSignatureEx(LPCWSTR pwszSourceFile);

void WINAPI ASN(void);

int WINAPI SignatureVerification(_In_ unsigned int argc, _In_reads_(argc) PCWSTR wargv[]);

DWORD WINAPI VerifyEmbeddedSignatures(_In_ PCWSTR FileName,
                                      _In_ HANDLE FileHandle,
                                      _In_ BOOL UseStrongSigPolicy);

int WINAPI GetInformationFromAuthenticodeSignedExecutables(int argc, TCHAR * argv[]);

void WINAPI SigningDataWithCNG(int argc, __in_ecount(argc) LPWSTR * wargv);

void WINAPI DsaSignHash(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                     _In_ ULONG PrivateKeyLen,
                     _In_reads_bytes_(DataSize) PUCHAR Data,
                     _In_ ULONG DataSize,
                     _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                     _In_ ULONG * SignSize
);

void WINAPI DsaVerifySignature(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                            _In_ ULONG PublicKeyLen,
                            _In_reads_bytes_(DataSize) PUCHAR Data,
                            _In_ ULONG DataSize,
                            _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                            _In_ ULONG SignSize
);

void WINAPI DsaVerifySignature(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                               _In_ ULONG PublicKeyLen,
                               _In_reads_bytes_(DataSize) PUCHAR Data,
                               _In_ ULONG DataSize,
                               _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                               _In_ ULONG SignSize
);

void WINAPI EcdsaSignHash(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                          _In_ ULONG PrivateKeyLen,
                          _In_reads_bytes_(DataSize) PUCHAR Data,
                          _In_ ULONG DataSize,
                          _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                          _In_ ULONG * SignSize
);

void WINAPI EcdsaVerifySignature(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                 _In_ ULONG PublicKeyLen,
                                 _In_reads_bytes_(DataSize) PUCHAR Data,
                                 _In_ ULONG DataSize,
                                 _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                                 _In_ ULONG SignSize
);


//////////////////////////////////////////////////////////////////////////////////////////////////
//哈希


BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize
);

DWORD WINAPI GetFileHash(_In_ LPCWSTR lpFileName,
                         _In_z_ LPCWSTR pszAlgId,
                         _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                         _In_ ULONG * HashSize
);


//////////////////////////////////////////////////////////////////////////////////////////////////


int WINAPI GetFileZoneIdentifier(int argc, wchar_t ** argv);
int WINAPI MapFileZoneIdentifier(int argc, wchar_t ** argv);
int WINAPI SetFileZoneIdentifier(int argc, wchar_t ** argv);
int WINAPI RemoveFileZoneIdentifier(int argc, wchar_t ** argv);

void WINAPI EnumCatAttributes(_In_ LPWSTR FilePath);

HRESULT WINAPI EnumInstalledProviders(void);

void WINAPI ExportSessionKey(void);

int WINAPI ImportPlaintextKey();

void WINAPI CreatingKeyContainerGeneratingKeys(void);

void WINAPI AcquireCryptContext(void);

void WINAPI DerivingSessionKeyFromPassword();

void WINAPI DuplicatingSessionKey();

void WINAPI SessionKeyParameters();

int WINAPI DiffieHellman(int argc, wchar_t * argv[]);

void WINAPI EnumSslProtocolProviders();

void WINAPI EnumProvidersByCrypt();

void WINAPI EnumProviderTypes();

void WINAPI EnumCsp();

void WINAPI GetFileVersion(PWCHAR FileName, VS_FIXEDFILEINFO * FileInfo);
void WINAPI GetFileResourcesW(IN LPCWSTR FileName, IN LPCWSTR ResourceName);

int WINAPI EnumFile(const TCHAR * Directory, FileCallBack CallBack, _In_opt_ PVOID Context);

void WINAPI EnumVolumes();
void WINAPI DisplayingVolumePaths(void);
void WINAPI EnumeratingVolumeGUIDPaths(void);


//////////////////////////////////////////////////////////////////////////////////////////////////
//加解密

BOOL WINAPI MyEncryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword);
BOOL WINAPI MyDecryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword);

void WINAPI EncryptingDataWithCNG(int argc, __in_ecount(argc) LPWSTR * wargv);

void WINAPI EnumProviders1();
void WINAPI EnumProviders2();

void WINAPI EnumAlgorithms();
void WINAPI EnumProviders(_In_z_  LPCWSTR pszAlgId);

NTSTATUS WINAPI EnumContexts_SystemAlloc();
NTSTATUS WINAPI EnumContexts_SelfAlloc();

NTSTATUS WINAPI EnumContextFunctions();
NTSTATUS WINAPI EnumContextFunctionProviders();

VOID WINAPI RsaPublicKeyEncrypt(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                _In_ ULONG PublicKeyLen,
                                _In_reads_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                _In_ ULONG PlainTextSize,
                                _Out_writes_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                _In_ ULONG CipherTextSize);
VOID WINAPI RsaPrivateKeyDecrypt(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                                 _In_ ULONG PrivateKeyLen,
                                 _In_reads_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                 _In_ ULONG CipherTextSize,
                                 _Out_writes_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                 _In_ ULONG PlainTextSize);

VOID WINAPI RsaPrivateKeyEncrypt(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey, 
                                 _In_ ULONG PrivateKeyLen,
                                _In_reads_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                _In_ ULONG PlainTextSize,
                                _Out_writes_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                _In_ ULONG CipherTextSize);
VOID WINAPI RsaPublicKeyDecrypt(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey, 
                                _In_ ULONG PublicKeyLen,
                                 _In_reads_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                 _In_ ULONG CipherTextSize,
                                 _Out_writes_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                 _In_ ULONG PlainTextSize);

void WINAPI EnumStorageProviders();


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
