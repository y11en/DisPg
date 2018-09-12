/*
*
* Copyright (c) 2015-2018 by blindtiger ( blindtiger@foxmail.com )
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. SEe the License
* for the specific language governing rights and limitations under the
* License.
*
* The Initial Developer of the Original e is blindtiger.
*
*/

#ifndef _CTX_H_
#define _CTX_H_

#include "Stack.h"

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

    typedef struct _SCB *PSCB;

    typedef struct _RTX {
        USHORT Platform;
        PPS_APC_ROUTINE ApcRoutine;
        PUSER_THREAD_START_ROUTINE StartRoutine;
        PVOID StartContext;
        PVOID Notify;
        NTSTATUS ReturnedStatus;

        ULONG64 Parameter[MAX_STACK_DEPTH];

        ULONG Index;
        ULONG Count;
        CALLERS Callers[MAX_STACK_DEPTH];
    }RTX, *PRTX;

    typedef struct _CTX {
        KAPC Apc;
        KEVENT Notify;
        RTX Rtx;
    } CTX, *PCTX;

    typedef struct _VTX32 {
        ULONG Eax;
        ULONG Ecx;
        ULONG Edx;

        ULONG EFlags;

        ULONG Esp;
        ULONG Eip;
    }VTX32, *PVTX32;

#ifdef _WIN64
    typedef struct _VTX64 {
        ULONG64 Routine;
        ULONG64 Context;
        ULONG64 Notify;

        ULONG64 Rax;
        ULONG64 Rcx;
        ULONG64 Rdx;
        ULONG64 R8;
        ULONG64 R9;
        ULONG64 R10;
        ULONG64 R11;
        ULONG64 EFlags;
        ULONG64 MxCsr;

        M128A Xmm0;
        M128A Xmm1;
        M128A Xmm2;
        M128A Xmm3;
        M128A Xmm4;
        M128A Xmm5;

        ULONG64 Rsp;
        ULONG64 Rip;
    }VTX64, *PVTX64;
#endif // _WIN64

    NTSTATUS
        NTAPI
        RemoteCall(
            __in HANDLE UniqueThread,
            __in USHORT Platform,
            __in_opt PUSER_THREAD_START_ROUTINE StartRoutine,
            __in_opt PVOID StartContext
        );

    NTSTATUS
        NTAPI
        UserRemoteCall(
            __in HANDLE UniqueThread,
            __in PSCB Scb,
            __in USHORT Platform,
            __in_opt PUSER_THREAD_START_ROUTINE StartRoutine,
            __in_opt PVOID StartContext
        );

    DECLSPEC_NOINLINE
        ULONG
        NTAPI
        WalkFrameChain(
            __out PCALLERS Callers,
            __in ULONG Count
        );

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_CTX_H_
