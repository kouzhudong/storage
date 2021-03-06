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

#include <Winsock2.h>
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <crtdbg.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <fltuser.h>
#include <locale.h>
#include <Lmserver.h>
#include <stdarg.h>
#include <wincrypt.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <aclapi.h>
#include <VersionHelpers.h>
#include <ShlDisp.h>
#include <Shlobj.h>
#include <Softpub.h>
#include <mscat.h>
//#include <SubAuth.h>
//#include <LsaLookup.h>
#include <WinUser.h>
#include <direct.h>
#include <sddl.h>
#include <ws2tcpip.h>
#include <fwpsu.h>
#include <atlbase.h>
#include <mbnapi.h>
#include <iostream>
#include <netfw.h>
#include <atlcomcli.h>
#include <objbase.h>
#include <oleauto.h>
#include <atlconv.h>
#define _WS2DEF_
#include <mstcpip.h>
#include <Intshcut.h>
//#include <winternl.h>
#include <SubAuth.h>
//#include <NTSecAPI.h>
//#include <ntdef.h>
//#include <netioapi.h>
#include <atlstr.h>
#include <comutil.h>
#include <wbemidl.h>
#include <dbt.h>
#include <lm.h>
#include <winnetwk.h>
#include <ws2spi.h>
#include <comdef.h>

#include <initguid.h> //注意前后顺序。静态定义UUID用的，否则：error LNK2001。
#include <usbioctl.h>
#include <usbiodef.h>
//#include <usbctypes.h>
#include <intsafe.h>
#include <specstrings.h>
#include <usb.h>
#include <usbuser.h>

#include <wincon.h> 
#include <time.h> 
#include <fwpmu.h>
#include <conio.h>
#include <nb30.h>

#pragma comment(lib, "fwpuclnt.lib") 
#pragma comment(lib, "Rpcrt4.lib")

#pragma comment(lib, "mpr.lib")

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Version.lib") 
//#pragma comment (lib,"Url.lib")
#pragma comment(lib, "wbemuuid.lib")

#include <bcrypt.h>
#pragma comment (lib, "Bcrypt.lib")

#include <shellapi.h>
#pragma comment (lib, "Shell32.lib")

#include <ncrypt.h>
#pragma comment (lib, "Ncrypt.lib")

#include <wintrust.h>
#pragma comment (lib, "wintrust.lib")

#include <Setupapi.h>
#pragma comment (lib,"Setupapi.lib")

#include <Shlwapi.h>
#pragma comment (lib,"Shlwapi.lib")

#include <DbgHelp.h>
#pragma comment (lib,"DbgHelp.lib")

#include <psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <Sfc.h>
#pragma comment(lib, "Sfc.lib")

//#include <winsock.h>
#pragma comment(lib, "Ws2_32.lib")

#pragma comment(lib,"Netapi32.lib")

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")

#include <Sensapi.h>
#pragma comment (lib,"Sensapi.lib")

#include <string>
#include <list>
#include <regex>
#include <map>
#include <set>

using namespace std;


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


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

int WINAPI CppShellKnownFolders(int argc, _TCHAR * argv[]);

void WINAPI GetImageFilePath(_Out_ LPWSTR ImageFilePath, _In_ DWORD nSize);

void WINAPI GetSpecialFolderPath();

LONG WINAPI VerifyEmbeddedSignatureEx(LPCWSTR pwszSourceFile);

void WINAPI ASN(void);

int WINAPI SignatureVerification(_In_ unsigned int argc, _In_reads_(argc) PCWSTR wargv[]);

DWORD WINAPI VerifyEmbeddedSignatures(_In_ PCWSTR FileName,
                                      _In_ HANDLE FileHandle,
                                      _In_ bool UseStrongSigPolicy);

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

int WINAPI DiffieHellman(int argc, _TCHAR * argv[]);

void WINAPI EnumProvidersByCrypt();

void WINAPI EnumProviderTypes();

void WINAPI EnumCsp(int argc, _TCHAR * argv[]);


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
