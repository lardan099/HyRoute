/* Minimal Win32 surface needed by the WinDivert filter compiler. */
#pragma once
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef int BOOL; typedef unsigned char BOOLEAN, UINT8, BYTE; typedef char CHAR, INT8;
typedef int16_t INT16; typedef uint16_t UINT16; typedef int32_t INT32, LONG; typedef uint32_t UINT32, UINT, DWORD, ULONG;
typedef int64_t INT64, LONGLONG; typedef uint64_t UINT64, ULONGLONG; typedef size_t SIZE_T; typedef void VOID, *PVOID, *LPVOID, *HANDLE;
typedef const char *LPCSTR; typedef char *PCHAR; typedef UINT *PUINT; typedef UINT8 *PUINT8; typedef UINT16 *PUINT16; typedef UINT32 *PUINT32; typedef UINT64 *PUINT64;
typedef void *LPOVERLAPPED; typedef wchar_t WCHAR, *LPWSTR; typedef const wchar_t *LPCWSTR; typedef int INT; typedef INT *PINT; typedef uintptr_t UINT_PTR, ULONG_PTR;
#define TRUE 1
#define FALSE 0
#define WINAPI
#define __in
#define __out
#define __inout
#define __in_opt
#define __out_opt
#define __inout_opt
#define __out_bcount(x)
#define __in_bcount(x)
#define __out_bcount_part_opt(a,b)
#define __in_ecount(x)
#define __out_ecount(x)
#define __out_bcount_opt(x)
#define __in_bcount_opt(x)
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_NO_DATA 232
#define HEAP_ZERO_MEMORY 8
static DWORD last_err; static void SetLastError(DWORD e){last_err=e;} static DWORD GetLastError(void){return last_err;}
static HANDLE HeapCreate(DWORD a, SIZE_T b, SIZE_T c){return (HANDLE)1;}
static BOOL HeapDestroy(HANDLE h){return TRUE;}
static LPVOID HeapAlloc(HANDLE h, DWORD f, SIZE_T n){return calloc(1,n);}
static BOOL HeapFree(HANDLE h, DWORD f, LPVOID p){free(p);return TRUE;}
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define DEBUG(...)
typedef union { struct { DWORD LowPart; DWORD HighPart; }; UINT64 QuadPart; } ULARGE_INTEGER;

#define WINDIVERT_INLINE inline
#include <limits.h>
#define HEAP_NO_SERIALIZE 1
#define ERROR_SUCCESS 0
