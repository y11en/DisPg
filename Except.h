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

#ifndef _EXCEPT_H_
#define _EXCEPT_H_

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

#define DivideErrorFault        0  
#define DebugTrapOrFault        1  
#define NmiInterrupt            2  
#define BreakpointTrap          3  
#define OverflowTrap            4  
#define BoundFault              5  
#define InvalidOpcodeFault      6  
#define NpxNotAvailableFault    7  
#define DoubleFaultAbort        8  
#define NpxSegmentOverrunAbort  9  
#define InvalidTssFault         10 
#define SegmentNotPresentFault  11 
#define StackFault              12 
#define GeneralProtectionFault  13 
#define PageFault               14 
#define FloatingErrorFault      16 
#define AlignmentFault          17 
#define McheckAbort             18 
#define XmmException            19 
#define ApcInterrupt            31 
#define RaiseAssertion          44 
#define DebugServiceTrap        45 
#define DpcInterrupt            47 
#define IpiInterrupt            225

#ifndef _WIN64
    typedef struct _DISPATCHER_CONTEXT {
        PEXCEPTION_REGISTRATION_RECORD RegistrationPointer;
    } DISPATCHER_CONTEXT;
#endif // !_WIN64

#define MAXIMUM_USER_FUNCTION_TABLE_SIZE 512
#define MAXIMUM_KERNEL_FUNCTION_TABLE_SIZE 256

    typedef struct _FUNCTION_TABLE_ENTRY32 {
        ULONG FunctionTable;
        ULONG ImageBase;
        ULONG SizeOfImage;
        ULONG SizeOfTable;
    } FUNCTION_TABLE_ENTRY32, *PFUNCTION_TABLE_ENTRY32;

    C_ASSERT(sizeof(FUNCTION_TABLE_ENTRY32) == 0x10);

    typedef struct _FUNCTION_TABLE_ENTRY64 {
        ULONG64 FunctionTable;
        ULONG64 ImageBase;
        ULONG SizeOfImage;
        ULONG SizeOfTable;
    } FUNCTION_TABLE_ENTRY64, *PFUNCTION_TABLE_ENTRY64;

    C_ASSERT(sizeof(FUNCTION_TABLE_ENTRY64) == 0x18);

    typedef struct _FUNCTION_TABLE {
        ULONG CurrentSize;
        ULONG MaximumSize;
        ULONG Epoch;
        BOOLEAN Overflow;
        ULONG TableEntry[1];
    } FUNCTION_TABLE, *PFUNCTION_TABLE;

    C_ASSERT(FIELD_OFFSET(FUNCTION_TABLE, TableEntry) == 0x10);

    typedef struct _FUNCTION_TABLE_SPECIAL {
        ULONG CurrentSize;
        ULONG MaximumSize;
        BOOLEAN Overflow;
        ULONG TableEntry[1];
    } FUNCTION_TABLE_SPECIAL, *PFUNCTION_TABLE_SPECIAL;

    C_ASSERT(FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) == 0xc);

    typedef
        VOID
        (*PKI_INTERRUPT_HANDLER) (
            VOID
            );

    ULONG
        NTAPI
        EncodeSystemPointer(
            __in ULONG Pointer
        );

    ULONG
        NTAPI
        DecodeSystemPointer(
            __in ULONG Pointer
        );

    VOID
        NTAPI
        CaptureImageExceptionValues(
            __in PVOID Base,
            __out PVOID * FunctionTable,
            __out PULONG TableSize
        );

    VOID
        NTAPI
        InitializeExcept(
            VOID
        );

    VOID
        NTAPI
        InsertUserInvertedFunctionTable(
            __in PVOID ImageBase,
            __in ULONG SizeOfImage
        );

    VOID
        NTAPI
        RemoveUserInvertedFunctionTable(
            __in PVOID ImageBase
        );

#ifndef _WIN64
    PVOID
        NTAPI
        DetourRtlLookupFunctionTable(
            __in PVOID ControlPc,
            __out PVOID * ImageBase,
            __out PULONG SizeOfTable
        );

    BOOLEAN
        NTAPI
        IsValidHandler(
            __in PEXCEPTION_ROUTINE Handler
        );

    VOID
        NTAPI
        InsertUserSpecialInvertedFunctionTable(
            __in PVOID ImageBase,
            __in ULONG SizeOfImage
        );

    VOID
        NTAPI
        RemoveUserSpecialInvertedFunctionTable(
            __in PVOID ImageBase
        );
#else
    PRUNTIME_FUNCTION
        NTAPI
        DetourRtlLookupFunctionTable(
            __in PVOID ControlPc,
            __out PVOID * ImageBase,
            __out PULONG SizeOfTable
        );

    PRUNTIME_FUNCTION
        NTAPI
        DetourRtlLookupFunctionEntry(
            __in ULONG64 ControlPc,
            __out PULONG64 ImageBase,
            __inout_opt PUNWIND_HISTORY_TABLE HistoryTable
        );

    VOID
        NTAPI
        SaveProcessorControlState(
            __out PKPROCESSOR_STATE ProcessorState
        );

    VOID
        NTAPI
        RestoreProcessorControlState(
            __out PKPROCESSOR_STATE ProcessorState
        );

    VOID
        NTAPI
        InsertInvertedFunctionTable(
            __in PVOID ImageBase,
            __in ULONG SizeOfImage
        );

    VOID
        NTAPI
        RemoveInvertedFunctionTable(
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        InsertWx86UserInvertedFunctionTable(
            __in PVOID ImageBase,
            __in ULONG SizeOfImage
        );

    VOID
        NTAPI
        RemoveWx86UserInvertedFunctionTable(
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        InsertWx86UserSpecialInvertedFunctionTable(
            __in PVOID ImageBase,
            __in ULONG SizeOfImage
        );

    VOID
        NTAPI
        RemoveWx86UserSpecialInvertedFunctionTable(
            __in PVOID ImageBase
        );
#endif // !_WIN64

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_EXCEPT_H_
