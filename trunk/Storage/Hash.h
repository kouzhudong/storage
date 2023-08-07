#pragma once

class Hash
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


#define BUFSIZE 1024
#define MD5LEN  16


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C
__declspec(dllexport)
BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize
);

EXTERN_C
__declspec(dllexport)
DWORD WINAPI GetFileHash(_In_ LPCWSTR lpFileName,
                         _In_z_ LPCWSTR pszAlgId,
                         _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                         _In_ ULONG * HashSize
);


//////////////////////////////////////////////////////////////////////////////////////////////////
