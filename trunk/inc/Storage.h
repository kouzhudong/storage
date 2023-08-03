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

int WINAPI CppShellKnownFolders(int argc, wchar_t * argv[]);

void WINAPI GetImageFilePath(_Out_ LPWSTR ImageFilePath, _In_ DWORD nSize);

BOOL WINAPI DelDirByApi(_In_ LPCWSTR Dir);
void WINAPI DelDirByShell(_In_ LPCWSTR Dir);

void WINAPI GetSpecialFolderPath();

LONG WINAPI VerifyEmbeddedSignatureEx(LPCWSTR pwszSourceFile);

void WINAPI ASN(void);

int WINAPI SignatureVerification(_In_ unsigned int argc, _In_reads_(argc) PCWSTR wargv[]);

DWORD WINAPI VerifyEmbeddedSignatures(_In_ PCWSTR FileName,
                                      _In_ HANDLE FileHandle,
                                      _In_ BOOL UseStrongSigPolicy);

int WINAPI GetInformationFromAuthenticodeSignedExecutables(int argc, TCHAR * argv[]);

int WINAPI GetFileZoneIdentifier(int argc, wchar_t ** argv);
int WINAPI MapFileZoneIdentifier(int argc, wchar_t ** argv);
int WINAPI SetFileZoneIdentifier(int argc, wchar_t ** argv);
int WINAPI RemoveFileZoneIdentifier(int argc, wchar_t ** argv);

void WINAPI EnumCatAttributes(_In_ LPWSTR FilePath);

HRESULT WINAPI EnumProviders(void);

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

void WINAPI EnumCsp(int argc, wchar_t * argv[]);

void WINAPI GetFileVersion(PWCHAR FileName, VS_FIXEDFILEINFO * FileInfo);
void WINAPI GetFileResourcesW(IN LPCWSTR FileName, IN LPCWSTR ResourceName);

int WINAPI EnumFile(const TCHAR * Directory, FileCallBack CallBack, _In_opt_ PVOID Context);

void WINAPI EnumVolumes();
void WINAPI DisplayingVolumePaths(void);
void WINAPI EnumeratingVolumeGUIDPaths(void);

BOOL WINAPI MyEncryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword);
BOOL WINAPI MyDecryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword);

void WINAPI EncryptingDataWithCNG(int argc, __in_ecount(argc) LPWSTR * wargv);


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
