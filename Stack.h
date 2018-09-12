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

#ifndef _STACK_H_
#define _STACK_H_

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

#ifndef _WIN64
#define STACK_ALIGN (8UI32)
#define STACK_ROUND (STACK_ALIGN - 1)

#define PSPALIGN_DOWN(address,amt) ((ULONG)(address) & ~(( amt ) - 1))
#define PSPALIGN_UP(address,amt) (PSPALIGN_DOWN( (address + (amt) - 1), (amt) ))

#define GetBaseExceptionFrame(Thread) (NULL)
#else
    typedef struct _KSTACK_SEGMENT_SPECIAL {
        ULONG_PTR StackBase;
        ULONG_PTR StackLimit;
        ULONG_PTR KernelStack;
        ULONG_PTR InitialStack;
        ULONG_PTR ActualLimit;
    } KSTACK_SEGMENT_SPECIAL, *PKSTACK_SEGMENT_SPECIAL;

    typedef struct _KSTACK_CONTROL_SPECIAL {
        KSTACK_SEGMENT_SPECIAL Current;
        KSTACK_SEGMENT_SPECIAL Previous;
    } KSTACK_CONTROL_SPECIAL, *PKSTACK_CONTROL_SPECIAL;

    typedef struct _KSTACK_SEGMENT {
        ULONG_PTR StackBase;
        ULONG_PTR StackLimit;
        ULONG_PTR KernelStack;
        ULONG_PTR InitialStack;
    } KSTACK_SEGMENT, *PKSTACK_SEGMENT;

    typedef struct _KSTACK_CONTROL {
        ULONG_PTR StackBase;

        union {
            ULONG_PTR ActualLimit;
            BOOLEAN StackExpansion : 1;
        };

        KSTACK_SEGMENT Previous;
    }KSTACK_CONTROL, *PKSTACK_CONTROL;

#define GetBaseExceptionFrame(Thread) \
            ((PKEXCEPTION_FRAME)((ULONG_PTR)GetBaseTrapFrame(Thread) - KEXCEPTION_FRAME_LENGTH))
#endif // !_WIN64

    typedef struct _CALLERS {
        PVOID * EstablisherFrame;
        PVOID Establisher;
    }CALLERS, *PCALLERS;

    PKTRAP_FRAME
        NTAPI
        GetBaseTrapFrame(
            __in PETHREAD Thread
        );

    VOID
        NTAPI
        PrintSymbol(
            __in PVOID Address
        );

    VOID
        NTAPI
        PrintFrameChain(
            __in_opt ULONG FramesToSkip
        );

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_STACK_H_
