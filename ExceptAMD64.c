/*
*
* Copyright (c) 2015-2018 by blindtiger ( blindtiger@foxmail.com )
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License")); you may not use this file except in compliance with
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

#include <OsDefs.h>

#include <kd.h>

#include "Debug.h"
#include "Except.h"
#include "Jump.h"
#include "Guard.h"
#include "Reload.h"
#include "Scan.h"
#include "Stack.h"
#include "Testis.h"
#include "Thread.h"

#ifndef PgIntercept
// #define PgIntercept
#endif // !PgIntercept

static PFUNCTION_TABLE InvertedFunctionTable;
static PFUNCTION_TABLE UserInvertedFunctionTable;
static PFUNCTION_TABLE Wx86UserInvertedFunctionTable;
static PFUNCTION_TABLE_SPECIAL Wx86UserSpecialInvertedFunctionTable;

PRUNTIME_FUNCTION
(NTAPI * NtosRtlLookupFunctionEntry)(
    __in ULONG64 ControlPc,
    __out PULONG64 ImageBase,
    __inout_opt PUNWIND_HISTORY_TABLE HistoryTable
    );

VOID
(NTAPI * NtosKeContextFromKframes)(
    __in PKTRAP_FRAME TrapFrame,
    __in PKEXCEPTION_FRAME ExceptionFrame,
    __inout PCONTEXT ContextRecord
    );

VOID
(NTAPI * NtosKiDispatchException)(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PKEXCEPTION_FRAME ExceptionFrame,
    __in PKTRAP_FRAME TrapFrame,
    __in KPROCESSOR_MODE PreviousMode,
    __in BOOLEAN FirstChance
    );

BOOLEAN
(NTAPI * NtosRtlDispatchException)(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PCONTEXT ContextRecord
    );

EXCEPTION_DISPOSITION
(NTAPI * Ntos__C_specific_handler)(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PVOID EstablisherFrame,
    __inout PCONTEXT ContextRecord,
    __inout PDISPATCHER_CONTEXT DispatcherContext
    );

VOID
NTAPI
_NLG_Notify(
    __in PVOID Destination,
    __in PVOID FramePointer,
    __in ULONG Code
);

VOID
NTAPI
__NLG_Return(
    VOID
);

EXCEPTION_DISPOSITION
NTAPI
ExecuteHandlerForException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PVOID EstablisherFrame,
    __inout PCONTEXT ContextRecord,
    __inout PVOID DispatcherContext
);

NTSTATUS
NTAPI
ProtectUserPages(
    __inout PVOID BaseAddress,
    __inout SIZE_T RegionSize,
    __in ULONG NewProtect,
    __out PULONG OldProtect
);

NTSTATUS
NTAPI
CopyStub(
    __in_opt PVOID BaseAddress,
    __in_bcount(BufferSize) CONST VOID * Buffer,
    __in SIZE_T BufferSize
);

VOID
NTAPI
DetourKiDispatchException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PKEXCEPTION_FRAME ExceptionFrame,
    __in PKTRAP_FRAME TrapFrame,
    __in KPROCESSOR_MODE PreviousMode,
    __in BOOLEAN FirstChance
);

EXCEPTION_DISPOSITION
NTAPI
Detour__C_specific_handler(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PVOID EstablisherFrame,
    __inout PCONTEXT ContextRecord,
    __inout PDISPATCHER_CONTEXT DispatcherContext
);

BOOLEAN
NTAPI
DetourRtlDispatchException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PCONTEXT ContextRecord
);

VOID
NTAPI
InitializeExcept(
    VOID
)
{
    PKPROCESSOR_STATE ProcessorState = NULL;
    KIDT_HANDLER_ADDRESS Handler = { 0 };
    PKIDTENTRY64 Idt = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    PVOID ImageBase = NULL;
    ULONG Length = 0;
    PRUNTIME_FUNCTION FunctionEntry = NULL;

    CHAR KeContextFromKframesSig[] = "e8 ?? ?? ?? ?? 81 3b 03 00 00 80";

#ifdef PgIntercept
    CHAR RtlDispatchExceptionSig[] = { 0xc7, 0x44, 0x24, 0x24, 0x01, 0x00, 0x00, 0x00, 0xe8 };
#endif // PgIntercept

    DisPg();

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        ControlPc = GetProcedureAddress(
            ImageBase,
            "RtlLookupFunctionEntry",
            0);

        if (NULL != ControlPc) {
#ifndef VMP
            DbgPrint(
                "Soul - Testis - < %p > RtlLookupFunctionEntry\n",
                ControlPc);
#endif // !VMP

            NtosRtlLookupFunctionEntry = BuildShadowJump(
                ControlPc,
                DetourRtlLookupFunctionEntry);
        }

#ifdef PgIntercept
        ControlPc = GetProcedureAddress(
            ImageBase,
            "__C_specific_handler",
            0);

        if (NULL != ControlPc) {
#ifndef VMP
            DbgPrint(
                "Soul - Testis - < %p > __C_specific_handler\n",
                ControlPc);
#endif // !VMP

            Ntos__C_specific_handler = BuildShadowJump(
                ControlPc,
                Detour__C_specific_handler);
        }

        ControlPc = GetProcedureAddress(
            ImageBase,
            "ExRaiseStatus",
            0);

        if (NULL != ControlPc) {
            FunctionEntry = DetourRtlLookupFunctionEntry(
                (ULONG64)ControlPc,
                (PULONG64)&ImageBase,
                NULL);

            if (NULL != FunctionEntry) {
                while (ControlPc <
                    (PCHAR)ImageBase + FunctionEntry->EndAddress) {
                    Length = GetInstructionLength(ControlPc);

                    if (sizeof(RtlDispatchExceptionSig) == RtlCompareMemory(
                        ControlPc,
                        RtlDispatchExceptionSig,
                        sizeof(RtlDispatchExceptionSig))) {
                        TargetPc = RVA_TO_VA(ControlPc + sizeof(RtlDispatchExceptionSig));

                        if (FALSE != MmIsAddressValid(TargetPc)) {
#ifndef VMP
                            DbgPrint(
                                "Soul - Testis - < %p > RtlDispatchException\n",
                                TargetPc);
#endif // !VMP

                            NtosRtlDispatchException = BuildShadowJump(
                                TargetPc,
                                DetourRtlDispatchException);
                        }

                        break;
                    }

                    ControlPc += Length;
                }
            }
        }
#endif // PgIntercept
    }

    ProcessorState = ExAllocatePool(
        NonPagedPool,
        sizeof(KPROCESSOR_STATE));

    if (NULL != ProcessorState) {
        SaveProcessorControlState(ProcessorState);

        Idt = ProcessorState->SpecialRegisters.Idtr.Base;

        Handler.OffsetLow = Idt[PageFault].OffsetLow;
        Handler.OffsetMiddle = Idt[PageFault].OffsetMiddle;
        Handler.OffsetHigh = Idt[PageFault].OffsetHigh;

        ControlPc = (PCHAR)Handler.Address;

        while (TRUE) {
            Length = GetInstructionLength(ControlPc);

            if (2 == Length) {
                if (0 == CmpByte(ControlPc[0], 0x48) &&
                    0 == CmpByte(ControlPc[1], 0xcf)) {
                    break;
                }
            }

            if (7 == Length) {
                if (0 == CmpByte(ControlPc[0], 0x4c) &&
                    0 == CmpByte(ControlPc[1], 0x8b) &&
                    0 == CmpByte(ControlPc[2], 0x85) &&
                    0 == CmpByte(ControlPc[3], 0xe8) &&
                    0 == CmpByte(ControlPc[4], 0x00) &&
                    0 == CmpByte(ControlPc[5], 0x00) &&
                    0 == CmpByte(ControlPc[6], 0x00)) {
                    ControlPc = RVA_TO_VA(ControlPc + 8);

                    if (FALSE != MmIsAddressValid(ControlPc)) {
                        while (TRUE) {
                            Length = GetInstructionLength(ControlPc);

                            if (2 == Length) {
                                if (0 == CmpByte(ControlPc[0], 0x48) &&
                                    0 == CmpByte(ControlPc[1], 0xcf)) {
                                    break;
                                }
                            }

                            if (3 == Length) {
                                if (0 == CmpByte(ControlPc[0], 0x48) &&
                                    0 == CmpByte(ControlPc[1], 0x8b) &&
                                    0 == CmpByte(ControlPc[3], 0xe8)) {
                                    TargetPc = RVA_TO_VA(ControlPc + 4);

                                    if (FALSE != MmIsAddressValid(TargetPc)) {
                                        FunctionEntry = DetourRtlLookupFunctionEntry(
                                            (ULONG64)TargetPc,
                                            (PULONG64)&ImageBase,
                                            NULL);

                                        if (NULL != FunctionEntry) {
                                            ControlPc = ScanBytes(
                                                (PCHAR)ImageBase + FunctionEntry->BeginAddress,
                                                (PCHAR)ImageBase + FunctionEntry->EndAddress,
                                                KeContextFromKframesSig);

                                            if (NULL != ControlPc) {
                                                NtosKeContextFromKframes = RVA_TO_VA(ControlPc + 1);

                                                if (FALSE != MmIsAddressValid(NtosKeContextFromKframes)) {
#ifndef VMP
                                                    DbgPrint(
                                                        "Soul - Testis - < %p > KeContextFromKframes\n",
                                                        NtosKeContextFromKframes);
#endif // !VMP
                                                }
                                            }
                                        }

#ifndef VMP
                                        DbgPrint(
                                            "Soul - Testis - < %p > KiDispatchException\n",
                                            TargetPc);
#endif // !VMP

                                        NtosKiDispatchException = BuildShadowJump(
                                            TargetPc,
                                            DetourKiDispatchException);
                                    }

                                    break;
                                }
                            }

                            ControlPc += Length;
                        }
                    }

                    break;
                }
            }

            ControlPc += Length;
        }

        ExFreePool(ProcessorState);
    }
}

PRUNTIME_FUNCTION
NTAPI
DetourRtlLookupFunctionTable(
    __in PVOID ControlPc,
    __out PVOID * ImageBase,
    __out PULONG SizeOfTable
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PKLDR_DATA_TABLE_ENTRY DataTableEntry = NULL;
    PRUNTIME_FUNCTION FunctionTable = NULL;

    Status = FindEntryForAllKernelAddress(
        (PVOID)ControlPc,
        &DataTableEntry);

    if (Status >= 0) {
        *ImageBase = DataTableEntry->DllBase;
        FunctionTable = DataTableEntry->ExceptionTable;
        *SizeOfTable = DataTableEntry->ExceptionTableSize;
    }

    return FunctionTable;
}

PRUNTIME_FUNCTION
NTAPI
DetourRtlLookupFunctionEntry(
    __in ULONG64 ControlPc,
    __out PULONG64 ImageBase,
    __inout_opt PUNWIND_HISTORY_TABLE HistoryTable
)
{
    PRUNTIME_FUNCTION FunctionEntry = NULL;
    PRUNTIME_FUNCTION FunctionTable = NULL;
    LONG High = 0;
    ULONG Index = 0;
    LONG Low = 0;
    LONG Middle = 0;
    ULONG RelativePc = 0;
    ULONG SizeOfTable = 0;

    if (NULL != NtosRtlLookupFunctionEntry) {
        FunctionEntry = NtosRtlLookupFunctionEntry(
            ControlPc,
            ImageBase,
            HistoryTable);
    }

    if (NULL == FunctionEntry) {
        FunctionTable = DetourRtlLookupFunctionTable(
            (PVOID)ControlPc,
            (PVOID *)ImageBase,
            &SizeOfTable);

        if (NULL != FunctionTable) {
            Low = 0;
            High = (SizeOfTable / sizeof(RUNTIME_FUNCTION)) - 1;
            RelativePc = (ULONG)(ControlPc - *ImageBase);

            while (High >= Low) {
                Middle = (Low + High) >> 1;
                FunctionEntry = &FunctionTable[Middle];

                if (RelativePc < FunctionEntry->BeginAddress) {
                    High = Middle - 1;
                }
                else if (RelativePc >= FunctionEntry->EndAddress) {
                    Low = Middle + 1;
                }
                else {
                    break;
                }
            }

            if (High < Low) {
                FunctionEntry = NULL;
            }
        }
        else {
            FunctionEntry = NULL;
        }

        if (NULL != FunctionEntry) {
            if (0 != (FunctionEntry->UnwindData & RUNTIME_FUNCTION_INDIRECT)) {
                FunctionEntry = (PRUNTIME_FUNCTION)
                    (FunctionEntry->UnwindData + *ImageBase - 1);
            }
        }
    }

    return FunctionEntry;
}

BOOLEAN
NTAPI
IsFrameInBounds(
    __inout PULONG64 LowLimit,
    __in ULONG64 StackFrame,
    __inout PULONG64 HighLimit
)
{
    BOOLEAN Result = FALSE;
    PKSTACK_CONTROL_SPECIAL StackControlSpecial = NULL;
    PKSTACK_CONTROL StackControl = NULL;

    if (0 == (StackFrame & 0x7)) {
        if (StackFrame < *LowLimit ||
            StackFrame >= *HighLimit) {
            if (FALSE == KeIsExecutingDpc()) {
                if (OsBuildNumber < 9200) {
                    StackControlSpecial = (PKSTACK_CONTROL_SPECIAL)
                        (*HighLimit - sizeof(KSTACK_CONTROL_SPECIAL));

                    if (StackControlSpecial->Previous.StackBase != 0) {
                        if (StackFrame >= StackControlSpecial->Previous.StackLimit &&
                            StackFrame < StackControlSpecial->Previous.StackBase) {
                            *LowLimit = StackControlSpecial->Previous.StackLimit;
                            *HighLimit = StackControlSpecial->Previous.StackBase;

                            Result = TRUE;
                        }
                    }
                }
                else {
                    StackControl = (PKSTACK_CONTROL)
                        (*HighLimit - sizeof(KSTACK_CONTROL));

                    if (StackControl->Previous.StackBase != 0) {
                        if (StackFrame >= StackControl->Previous.StackLimit &&
                            StackFrame < StackControl->Previous.StackBase) {
                            *LowLimit = StackControl->Previous.StackLimit;
                            *HighLimit = StackControl->Previous.StackBase;

                            Result = TRUE;
                        }
                    }
                }
            }
        }
        else {
            Result = TRUE;
        }
    }

    return Result;
}

VOID
NTAPI
CopyContext(
    __out PCONTEXT Destination,
    __in PCONTEXT Source
)
{
    Destination->Rip = Source->Rip;
    Destination->Rbx = Source->Rbx;
    Destination->Rsp = Source->Rsp;
    Destination->Rbp = Source->Rbp;
    Destination->Rsi = Source->Rsi;
    Destination->Rdi = Source->Rdi;
    Destination->R12 = Source->R12;
    Destination->R13 = Source->R13;
    Destination->R14 = Source->R14;
    Destination->R15 = Source->R15;
    Destination->Xmm6 = Source->Xmm6;
    Destination->Xmm7 = Source->Xmm7;
    Destination->Xmm8 = Source->Xmm8;
    Destination->Xmm9 = Source->Xmm9;
    Destination->Xmm10 = Source->Xmm10;
    Destination->Xmm11 = Source->Xmm11;
    Destination->Xmm12 = Source->Xmm12;
    Destination->Xmm13 = Source->Xmm13;
    Destination->Xmm14 = Source->Xmm14;
    Destination->Xmm15 = Source->Xmm15;
    Destination->SegCs = Source->SegCs;
    Destination->SegSs = Source->SegSs;
    Destination->MxCsr = Source->MxCsr;
    Destination->EFlags = Source->EFlags;
}

EXCEPTION_DISPOSITION
NTAPI
Detour__C_specific_handler(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PVOID EstablisherFrame,
    __inout PCONTEXT ContextRecord,
    __inout PDISPATCHER_CONTEXT DispatcherContext
)
{
    ULONG_PTR ControlPc = 0;
    PEXCEPTION_FILTER ExceptionFilter = NULL;
    EXCEPTION_POINTERS ExceptionPointers = { 0 };
    ULONG_PTR ImageBase = 0;
    ULONG_PTR Handler = 0;
    ULONG Index = 0;
    PSCOPE_TABLE ScopeTable = NULL;
    ULONG TargetIndex = 0;
    ULONG_PTR TargetPc = 0;
    PTERMINATION_HANDLER TerminationHandler = NULL;
    LONG Value = 0;

    ImageBase = DispatcherContext->ImageBase;
    ControlPc = DispatcherContext->ControlPc - ImageBase;
    ScopeTable = (PSCOPE_TABLE)(DispatcherContext->HandlerData);

    if (IS_DISPATCHING(ExceptionRecord->ExceptionFlags)) {
        ExceptionPointers.ExceptionRecord = ExceptionRecord;
        ExceptionPointers.ContextRecord = ContextRecord;

        for (Index = DispatcherContext->ScopeIndex;
            Index < ScopeTable->Count;
            Index += 1) {
            if ((ControlPc >= ScopeTable->ScopeRecord[Index].BeginAddress) &&
                (ControlPc < ScopeTable->ScopeRecord[Index].EndAddress) &&
                (ScopeTable->ScopeRecord[Index].JumpTarget != 0)) {
                if (ScopeTable->ScopeRecord[Index].HandlerAddress == 1) {
                    Value = EXCEPTION_EXECUTE_HANDLER;
                }
                else {
                    ExceptionFilter = (PEXCEPTION_FILTER)
                        (ScopeTable->ScopeRecord[Index].HandlerAddress + ImageBase);

#define EXECUTE_EXCEPTION_FILTER(ExceptionPointers, \
                                 EstablisherFrame, \
                                 ExceptionFilter, \
                                 DispatcherContext) \
    (ExceptionFilter)(ExceptionPointers, EstablisherFrame)

                    Value = EXECUTE_EXCEPTION_FILTER(
                        &ExceptionPointers,
                        EstablisherFrame,
                        ExceptionFilter,
                        DispatcherContext);
                }

                if (Value < 0) {
                    return ExceptionContinueExecution;
                }
                else if (Value > 0) {
                    Handler = ImageBase + ScopeTable->ScopeRecord[Index].JumpTarget;

                    _NLG_Notify(
                        (PVOID)Handler,
                        EstablisherFrame,
                        0x1);

                    RtlUnwindEx(
                        EstablisherFrame,
                        (PVOID)(ScopeTable->ScopeRecord[Index].JumpTarget + ImageBase),
                        ExceptionRecord,
                        (PVOID)((ULONG_PTR)ExceptionRecord->ExceptionCode),
                        (PCONTEXT)DispatcherContext->ContextRecord,
                        DispatcherContext->HistoryTable);

                    __NLG_Return();
                }
            }
        }
    }
    else {
#define DC_TARGETPC(DispatcherContext) ((DispatcherContext)->TargetIp)

        TargetPc = DC_TARGETPC(DispatcherContext) - ImageBase;

        for (Index = DispatcherContext->ScopeIndex;
            Index < ScopeTable->Count;
            Index += 1) {
            if ((ControlPc >= ScopeTable->ScopeRecord[Index].BeginAddress) &&
                (ControlPc < ScopeTable->ScopeRecord[Index].EndAddress)) {
                if (IS_TARGET_UNWIND(ExceptionRecord->ExceptionFlags)) {
                    for (TargetIndex = 0;
                        TargetIndex < ScopeTable->Count;
                        TargetIndex += 1) {
                        if ((TargetPc >= ScopeTable->ScopeRecord[TargetIndex].BeginAddress) &&
                            (TargetPc < ScopeTable->ScopeRecord[TargetIndex].EndAddress) &&
                            (ScopeTable->ScopeRecord[TargetIndex].JumpTarget ==
                                ScopeTable->ScopeRecord[Index].JumpTarget) &&
                                (ScopeTable->ScopeRecord[TargetIndex].HandlerAddress ==
                                    ScopeTable->ScopeRecord[Index].HandlerAddress)) {
                            break;
                        }
                    }

                    if (TargetIndex != ScopeTable->Count) {
                        break;
                    }
                }

                if (ScopeTable->ScopeRecord[Index].JumpTarget != 0) {
                    if ((TargetPc == ScopeTable->ScopeRecord[Index].JumpTarget) &&
                        (IS_TARGET_UNWIND(ExceptionRecord->ExceptionFlags))) {
                        break;
                    }
                }
                else {
                    DispatcherContext->ScopeIndex = Index + 1;

                    TerminationHandler = (PTERMINATION_HANDLER)
                        (ScopeTable->ScopeRecord[Index].HandlerAddress + ImageBase);

#define EXECUTE_TERMINATION_HANDLER(AbnormalTermination, \
                                    EstablisherFrame, \
                                    TerminationHandler, \
                                    DispatcherContext) \
    (TerminationHandler)(AbnormalTermination, EstablisherFrame)

                    EXECUTE_TERMINATION_HANDLER(
                        TRUE,
                        EstablisherFrame,
                        TerminationHandler,
                        DispatcherContext);
                }
            }
        }
    }

    return ExceptionContinueSearch;
}

BOOLEAN
NTAPI
DetourRtlDispatchException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PCONTEXT ContextRecord
)
{
    BOOLEAN Completion = FALSE;
    CONTEXT PreviousContext = { 0 };
    ULONG64 ControlPc = 0;
    DISPATCHER_CONTEXT DispatcherContext = { 0 };
    EXCEPTION_DISPOSITION Disposition = { 0 };
    ULONG64 EstablisherFrame = 0;
    ULONG ExceptionFlags = 0;
    PEXCEPTION_ROUTINE ExceptionRoutine = NULL;
    PRUNTIME_FUNCTION FunctionEntry = NULL;
    PVOID HandlerData = NULL;
    ULONG64 HighLimit = 0;
    PUNWIND_HISTORY_TABLE HistoryTable = NULL;
    ULONG64 ImageBase = 0;
    ULONG Index = 0;
    ULONG64 LowLimit = 0;
    ULONG64 NestedFrame = 0;
    BOOLEAN Repeat = FALSE;
    ULONG ScopeIndex = 0;
    UNWIND_HISTORY_TABLE UnwindTable = { 0 };

    CHAR Sig[] = {
        0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0xd1, 0x83,
        0xe1, 0x03, 0xff, 0xc1, 0x48, 0xd3, 0xc8, 0x4c,
        0x33, 0xc0, 0x4c, 0x33, 0xc8, 0x4c, 0x33, 0xd0,
        0x4c, 0x33, 0xd8, 0x33, 0xc0
    };

    IoGetStackLimits(&LowLimit, &HighLimit);
    CopyContext(&PreviousContext, ContextRecord);

    ControlPc = (ULONG64)ExceptionRecord->ExceptionAddress;
    ExceptionFlags = ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE;
    NestedFrame = 0;

    HistoryTable = &UnwindTable;
    HistoryTable->Count = 0;
    HistoryTable->Search = UNWIND_HISTORY_TABLE_NONE;
    HistoryTable->LowAddress = -1;
    HistoryTable->HighAddress = 0;

    do {
        FunctionEntry = DetourRtlLookupFunctionEntry(
            ControlPc,
            &ImageBase,
            NULL);

        if (NULL != FunctionEntry) {
            if (sizeof(Sig) == RtlCompareMemory(
                (PCHAR)ImageBase + FunctionEntry->BeginAddress,
                Sig,
                sizeof(Sig))) {
                __debugbreak();
            }

            ExceptionRoutine = RtlVirtualUnwind(
                UNW_FLAG_EHANDLER,
                ImageBase,
                ControlPc,
                FunctionEntry,
                &PreviousContext,
                &HandlerData,
                &EstablisherFrame,
                NULL);

            if (FALSE == IsFrameInBounds(
                &LowLimit,
                EstablisherFrame,
                &HighLimit)) {
                ExceptionFlags |= EXCEPTION_STACK_INVALID;
                break;
            }
            else if (NULL != ExceptionRoutine) {
                ScopeIndex = 0;

                do {
                    ExceptionRecord->ExceptionFlags = ExceptionFlags;

                    Repeat = FALSE;

                    DispatcherContext.ControlPc = ControlPc;
                    DispatcherContext.ImageBase = ImageBase;
                    DispatcherContext.FunctionEntry = FunctionEntry;
                    DispatcherContext.EstablisherFrame = EstablisherFrame;
                    DispatcherContext.ContextRecord = &PreviousContext;
                    DispatcherContext.LanguageHandler = ExceptionRoutine;
                    DispatcherContext.HandlerData = HandlerData;
                    DispatcherContext.HistoryTable = HistoryTable;
                    DispatcherContext.ScopeIndex = ScopeIndex;

                    Disposition = ExecuteHandlerForException(
                        ExceptionRecord,
                        (PVOID)EstablisherFrame,
                        ContextRecord,
                        &DispatcherContext);

                    ExceptionFlags |=
                        (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE);

                    if (NestedFrame == EstablisherFrame) {
                        ExceptionFlags &= ~EXCEPTION_NESTED_CALL;
                        NestedFrame = 0;
                    }

                    switch (Disposition) {
                    case ExceptionContinueExecution:
                        if ((ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0) {
                            ExRaiseStatus(STATUS_NONCONTINUABLE_EXCEPTION);
                        }
                        else {
                            Completion = TRUE;
                            goto DispatchExit;
                        }

                    case ExceptionContinueSearch:
                        break;

                    case ExceptionNestedException:
                        ExceptionFlags |= EXCEPTION_NESTED_CALL;

                        if (DispatcherContext.EstablisherFrame > NestedFrame) {
                            NestedFrame = DispatcherContext.EstablisherFrame;
                        }

                        break;

                    case ExceptionCollidedUnwind:
                        ControlPc = DispatcherContext.ControlPc;
                        ImageBase = DispatcherContext.ImageBase;
                        FunctionEntry = DispatcherContext.FunctionEntry;
                        EstablisherFrame = DispatcherContext.EstablisherFrame;

                        CopyContext(&PreviousContext, DispatcherContext.ContextRecord);

                        PreviousContext.Rip = ControlPc;
                        ExceptionRoutine = DispatcherContext.LanguageHandler;
                        HandlerData = DispatcherContext.HandlerData;
                        HistoryTable = DispatcherContext.HistoryTable;
                        ScopeIndex = DispatcherContext.ScopeIndex;
                        Repeat = TRUE;

                        break;

                    default:
                        ExRaiseStatus(STATUS_INVALID_DISPOSITION);
                    }

                } while (FALSE != Repeat);
            }
        }
        else {
            if (ControlPc == *(PULONG64)(PreviousContext.Rsp)) {
                break;
            }

            PreviousContext.Rip = *(PULONG64)(PreviousContext.Rsp);
            PreviousContext.Rsp += 8;
        }

        ControlPc = PreviousContext.Rip;
    } while (FALSE != IsFrameInBounds(&LowLimit, (ULONG64)PreviousContext.Rsp, &HighLimit));

    ExceptionRecord->ExceptionFlags = ExceptionFlags;

DispatchExit:
    return Completion;
}

VOID
NTAPI
DetourKiDispatchException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PKEXCEPTION_FRAME ExceptionFrame,
    __in PKTRAP_FRAME TrapFrame,
    __in KPROCESSOR_MODE PreviousMode,
    __in BOOLEAN FirstChance
)
{
    if (NULL != NtosKiDispatchException) {
        NtosKiDispatchException(
            ExceptionRecord,
            ExceptionFrame,
            TrapFrame,
            PreviousMode,
            FirstChance);
    }
}

VOID
NTAPI
SearchInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PSTR SectionName = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    USHORT Index = 0;
    SIZE_T Offset = 0;
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PFUNCTION_TABLE_ENTRY64 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (FALSE != MmIsAddressValid(NtHeaders)) {
            NtSection = IMAGE_FIRST_SECTION(NtHeaders);

            FunctionTableEntry = ExAllocatePool(
                NonPagedPool,
                sizeof(FUNCTION_TABLE_ENTRY64));

            if (NULL != FunctionTableEntry) {
                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry->FunctionTable = (ULONG64)FunctionTable;
                FunctionTableEntry->ImageBase = (ULONG64)ImageBase;
                FunctionTableEntry->SizeOfImage = GetSizeOfImage(ImageBase);
                FunctionTableEntry->SizeOfTable = SizeOfTable;

                for (Index = 0;
                    Index < NtHeaders->FileHeader.NumberOfSections;
                    Index++) {
                    SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                    SizeToLock = max(
                        NtSection[Index].SizeOfRawData,
                        NtSection[Index].Misc.VirtualSize);

                    if (FALSE != MmIsAddressValid(SectionBase)) {
                        if (IMAGE_SCN_CNT_INITIALIZED_DATA == FlagOn(
                            NtSection[Index].Characteristics,
                            IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                            for (Offset = 0;
                                Offset < AlignedToSize(
                                    SizeToLock,
                                    NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY64);
                                Offset += sizeof(PVOID)) {
                                FoundFunctionTableEntry = SectionBase + Offset;

                                if (sizeof(FUNCTION_TABLE_ENTRY64) == RtlCompareMemory(
                                    FoundFunctionTableEntry,
                                    FunctionTableEntry,
                                    sizeof(FUNCTION_TABLE_ENTRY64))) {
                                    do {
                                        InvertedFunctionTable = CONTAINING_RECORD(
                                            FoundFunctionTableEntry,
                                            FUNCTION_TABLE,
                                            TableEntry);

                                        if (InvertedFunctionTable->MaximumSize ==
                                            MAXIMUM_KERNEL_FUNCTION_TABLE_SIZE &&
                                            (InvertedFunctionTable->Overflow == TRUE ||
                                                InvertedFunctionTable->Overflow == FALSE)) {
                                            break;
                                        }

                                        FoundFunctionTableEntry--;
                                    } while (TRUE);

                                    goto exit;
                                }
                            }
                        }
                    }
                }

            exit:
                ExFreePool(FunctionTableEntry);
            }
        }
    }
}

VOID
NTAPI
InsertInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;

    if (NULL == InvertedFunctionTable) {
        SearchInvertedFunctionTable();
    }

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &InvertedFunctionTable->TableEntry;

        CurrentSize = InvertedFunctionTable->CurrentSize;

        ImageHandle = GetImageHandle("ntoskrnl.exe");

        if (NULL != ImageHandle &&
            ImageHandle == (PVOID)FunctionTableEntry[0].ImageBase) {
            Index = 1;
        }

        if (CurrentSize != InvertedFunctionTable->MaximumSize) {
            if (0 != CurrentSize) {
                for (;
                    Index < CurrentSize;
                    Index++) {
                    if ((ULONG64)ImageBase < FunctionTableEntry[Index].ImageBase) {
                        RtlMoveMemory(
                            &FunctionTableEntry[Index + 1],
                            &FunctionTableEntry[Index],
                            (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY64));

                        break;
                    }
                }
            }

            CaptureImageExceptionValues(
                ImageBase,
                &FunctionTable,
                &SizeOfTable);

            FunctionTableEntry[Index].ImageBase = (ULONG64)ImageBase;
            FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
            FunctionTableEntry[Index].FunctionTable = (ULONG64)FunctionTable;
            FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

            InvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
            DbgPrint(
                "Soul - Testis - insert inverted function table < %04d >\n",
                Index);
#endif // !VMP
        }
        else {
            InvertedFunctionTable->Overflow = TRUE;
        }
    }
}

VOID
NTAPI
RemoveInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &InvertedFunctionTable->TableEntry;

        CurrentSize = InvertedFunctionTable->CurrentSize;

        for (Index = 0;
            Index < CurrentSize;
            Index += 1) {
            if ((ULONG64)ImageBase == FunctionTableEntry[Index].ImageBase) {
                RtlMoveMemory(
                    &FunctionTableEntry[Index],
                    &FunctionTableEntry[Index + 1],
                    (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY64));

                InvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - remove inverted function table < %04d >\n",
                    Index);
#endif // !VMP

                break;
            }
        }
    }
}

VOID
NTAPI
SearchUserInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    USHORT Index = 0;
    SIZE_T Offset = 0;
    FUNCTION_TABLE_ENTRY64 FunctionTableEntry = { 0 };
    PFUNCTION_TABLE_ENTRY64 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    if (FALSE == PsIsSystemProcess(IoGetCurrentProcess())) {
        ImageBase = GetImageHandle("ntdll.dll");

        if (NULL != ImageBase) {
            NtHeaders = RtlImageNtHeader(ImageBase);

            if (FALSE != MmIsAddressValid(NtHeaders)) {
                NtSection = IMAGE_FIRST_SECTION(NtHeaders);

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry.FunctionTable = (ULONG64)FunctionTable;
                FunctionTableEntry.ImageBase = (ULONG64)ImageBase;
                FunctionTableEntry.SizeOfImage = GetSizeOfImage(ImageBase);
                FunctionTableEntry.SizeOfTable = SizeOfTable;

                for (Index = 0;
                    Index < NtHeaders->FileHeader.NumberOfSections;
                    Index++) {
                    if (0 != NtSection[Index].VirtualAddress) {
                        SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                        SizeToLock = max(
                            NtSection[Index].SizeOfRawData,
                            NtSection[Index].Misc.VirtualSize);

                        if (FALSE != MmIsAddressValid(SectionBase)) {
                            if (IMAGE_SCN_CNT_INITIALIZED_DATA == FlagOn(
                                NtSection[Index].Characteristics,
                                IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                                for (Offset = 0;
                                    Offset < AlignedToSize(
                                        SizeToLock,
                                        NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY64);
                                    Offset += sizeof(PVOID)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY64) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        &FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY64))) {
                                        do {
                                            UserInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE,
                                                TableEntry);

                                            if (UserInvertedFunctionTable->MaximumSize ==
                                                MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (UserInvertedFunctionTable->Overflow == TRUE ||
                                                    UserInvertedFunctionTable->Overflow == FALSE)) {
                                                break;
                                            }

                                            FoundFunctionTableEntry--;
                                        } while (TRUE);

                                        goto exit;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

exit:
    return;
}

VOID
NTAPI
SearchWx86UserInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    USHORT Index = 0;
    SIZE_T Offset = 0;
    FUNCTION_TABLE_ENTRY32 FunctionTableEntry = { 0 };
    PFUNCTION_TABLE_ENTRY32 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    if (FALSE == PsIsSystemProcess(IoGetCurrentProcess())) {
        ImageBase = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

        if (NULL != ImageBase) {
            NtHeaders = RtlImageNtHeader(ImageBase);

            if (FALSE != MmIsAddressValid(NtHeaders)) {
                NtSection = IMAGE_FIRST_SECTION(NtHeaders);

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry.FunctionTable = PtrToUlong(FunctionTable);
                FunctionTableEntry.ImageBase = PtrToUlong(ImageBase);
                FunctionTableEntry.SizeOfImage = GetSizeOfImage(ImageBase);
                FunctionTableEntry.SizeOfTable = SizeOfTable;

                for (Index = 0;
                    Index < NtHeaders->FileHeader.NumberOfSections;
                    Index++) {
                    if (0 != NtSection[Index].VirtualAddress) {
                        SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                        SizeToLock = max(
                            NtSection[Index].SizeOfRawData,
                            NtSection[Index].Misc.VirtualSize);

                        if (FALSE != MmIsAddressValid(SectionBase)) {
                            if (IMAGE_SCN_CNT_INITIALIZED_DATA == FlagOn(
                                NtSection[Index].Characteristics,
                                IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                                for (Offset = 0;
                                    Offset < AlignedToSize(
                                        SizeToLock,
                                        NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY32);
                                    Offset += sizeof(ULONG)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY32) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        &FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY32))) {
                                        do {
                                            Wx86UserInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE,
                                                TableEntry);

                                            if (Wx86UserInvertedFunctionTable->MaximumSize ==
                                                MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (Wx86UserInvertedFunctionTable->Overflow == TRUE ||
                                                    Wx86UserInvertedFunctionTable->Overflow == FALSE)) {
                                                break;
                                            }

                                            FoundFunctionTableEntry--;
                                        } while (TRUE);

                                        goto exit;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

exit:
    return;
}

VOID
NTAPI
SearchWx86UserSpecialInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    USHORT Index = 0;
    SIZE_T Offset = 0;
    FUNCTION_TABLE_ENTRY32 FunctionTableEntry = { 0 };
    PFUNCTION_TABLE_ENTRY32 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    if (FALSE == PsIsSystemProcess(IoGetCurrentProcess())) {
        ImageBase = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

        if (NULL != ImageBase) {
            NtHeaders = RtlImageNtHeader(ImageBase);

            if (FALSE != MmIsAddressValid(NtHeaders)) {
                NtSection = IMAGE_FIRST_SECTION(NtHeaders);

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry.FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                FunctionTableEntry.ImageBase = PtrToUlong(ImageBase);
                FunctionTableEntry.SizeOfImage = GetSizeOfImage(ImageBase);
                FunctionTableEntry.SizeOfTable = SizeOfTable;

                for (Index = 0;
                    Index < NtHeaders->FileHeader.NumberOfSections;
                    Index++) {
                    if (0 != NtSection[Index].VirtualAddress) {
                        SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                        SizeToLock = max(
                            NtSection[Index].SizeOfRawData,
                            NtSection[Index].Misc.VirtualSize);

                        if (FALSE != MmIsAddressValid(SectionBase)) {
                            if (IMAGE_SCN_CNT_INITIALIZED_DATA == FlagOn(
                                NtSection[Index].Characteristics,
                                IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                                for (Offset = 0;
                                    Offset < AlignedToSize(
                                        SizeToLock,
                                        NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY32);
                                    Offset += sizeof(ULONG)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY32) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        &FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY32))) {
                                        do {
                                            Wx86UserSpecialInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE_SPECIAL,
                                                TableEntry);

                                            if (Wx86UserSpecialInvertedFunctionTable->MaximumSize ==
                                                MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (Wx86UserSpecialInvertedFunctionTable->Overflow == TRUE ||
                                                    Wx86UserSpecialInvertedFunctionTable->Overflow == FALSE)) {
                                                break;
                                            }

                                            FoundFunctionTableEntry--;
                                        } while (TRUE);

                                        goto exit;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

exit:
    return;
}

VOID
NTAPI
InsertUserInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;
    ULONG OldProtect = 0;

    if (NULL == UserInvertedFunctionTable) {
        SearchUserInvertedFunctionTable();
    }

    if (NULL != UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &UserInvertedFunctionTable->TableEntry;

        CurrentSize = UserInvertedFunctionTable->CurrentSize;

        Status = ProtectUserPages(
            UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = GetImageHandle("ntdll.dll");

            if (NULL != ImageHandle &&
                ImageHandle == (PVOID)FunctionTableEntry[0].ImageBase) {
                Index = 1;
            }

            if (CurrentSize != UserInvertedFunctionTable->MaximumSize) {
                if (0 != CurrentSize) {
                    for (;
                        Index < CurrentSize;
                        Index++) {
                        if ((ULONG64)ImageBase < FunctionTableEntry[Index].ImageBase) {
                            RtlMoveMemory(
                                &FunctionTableEntry[Index + 1],
                                &FunctionTableEntry[Index],
                                (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY64));

                            break;
                        }
                    }
                }

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry[Index].ImageBase = (ULONG64)ImageBase;
                FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                FunctionTableEntry[Index].FunctionTable = (ULONG64)FunctionTable;
                FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                UserInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - insert user inverted function table < %04d >\n",
                    Index);
#endif // !VMP
            }
            else {
                UserInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectUserPages(
                UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveUserInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &UserInvertedFunctionTable->TableEntry;

        CurrentSize = UserInvertedFunctionTable->CurrentSize;

        Status = ProtectUserPages(
            UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            for (Index = 0;
                Index < CurrentSize;
                Index += 1) {
                if ((ULONG64)ImageBase == FunctionTableEntry[Index].ImageBase) {
                    RtlMoveMemory(
                        &FunctionTableEntry[Index],
                        &FunctionTableEntry[Index + 1],
                        (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY64));

                    UserInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remove user inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectUserPages(
                UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
InsertWx86UserInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;
    ULONG OldProtect = 0;

    if (NULL == Wx86UserInvertedFunctionTable) {
        SearchWx86UserInvertedFunctionTable();
    }

    if (NULL != Wx86UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserInvertedFunctionTable->CurrentSize;

        Status = ProtectUserPages(
            Wx86UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

            if (NULL != ImageHandle &&
                ImageHandle == UlongToPtr(FunctionTableEntry[0].ImageBase)) {
                Index = 1;
            }

            if (CurrentSize != Wx86UserInvertedFunctionTable->MaximumSize) {
                if (0 != CurrentSize) {
                    for (;
                        Index < CurrentSize;
                        Index++) {
                        if (PtrToUlong(ImageBase) < FunctionTableEntry[Index].ImageBase) {
                            RtlMoveMemory(
                                &FunctionTableEntry[Index + 1],
                                &FunctionTableEntry[Index],
                                (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY32));

                            break;
                        }
                    }
                }

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                if (LongToPtr(-1) != FunctionTable &&
                    -1 != SizeOfTable) {
                    FunctionTableEntry[Index].ImageBase = PtrToUlong(ImageBase);
                    FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                    FunctionTableEntry[Index].FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                    FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                    Wx86UserInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - insert wx86 user inverted function table < %04d >\n",
                        Index);
#endif // !VMP
                }
            }
            else {
                Wx86UserInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectUserPages(
                Wx86UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveWx86UserInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != Wx86UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserInvertedFunctionTable->CurrentSize;

        Status = ProtectUserPages(
            Wx86UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            for (Index = 0;
                Index < CurrentSize;
                Index += 1) {
                if (PtrToUlong(ImageBase) == FunctionTableEntry[Index].ImageBase) {
                    RtlMoveMemory(
                        &FunctionTableEntry[Index],
                        &FunctionTableEntry[Index + 1],
                        (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY32));

                    Wx86UserInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remove wx86 user inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectUserPages(
                Wx86UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
InsertWx86UserSpecialInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;
    ULONG OldProtect = 0;

    if (NULL == Wx86UserSpecialInvertedFunctionTable) {
        SearchWx86UserSpecialInvertedFunctionTable();
    }

    if (NULL != Wx86UserSpecialInvertedFunctionTable) {
        FunctionTableEntry =
            FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserSpecialInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserSpecialInvertedFunctionTable->CurrentSize;

        Status = ProtectUserPages(
            Wx86UserSpecialInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

            if (NULL != ImageHandle &&
                ImageHandle == UlongToPtr(FunctionTableEntry[0].ImageBase)) {
                Index = 1;
            }

            if (CurrentSize != Wx86UserSpecialInvertedFunctionTable->MaximumSize) {
                if (0 != CurrentSize) {
                    for (;
                        Index < CurrentSize;
                        Index++) {
                        if (PtrToUlong(ImageBase) < FunctionTableEntry[Index].ImageBase) {
                            RtlMoveMemory(
                                &FunctionTableEntry[Index + 1],
                                &FunctionTableEntry[Index],
                                (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY32));

                            break;
                        }
                    }
                }

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                if (LongToPtr(-1) != FunctionTable &&
                    -1 != SizeOfTable) {
                    FunctionTableEntry[Index].ImageBase = PtrToUlong(ImageBase);
                    FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                    FunctionTableEntry[Index].FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                    FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                    Wx86UserSpecialInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - insert wx86 user special inverted function table < %04d >\n",
                        Index);
#endif // !VMP
                }
            }
            else {
                Wx86UserSpecialInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectUserPages(
                Wx86UserSpecialInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveWx86UserSpecialInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != Wx86UserSpecialInvertedFunctionTable) {
        FunctionTableEntry =
            FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserSpecialInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserSpecialInvertedFunctionTable->CurrentSize;

        Status = ProtectUserPages(
            Wx86UserSpecialInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            for (Index = 0;
                Index < CurrentSize;
                Index += 1) {
                if (PtrToUlong(ImageBase) == FunctionTableEntry[Index].ImageBase) {
                    RtlMoveMemory(
                        &FunctionTableEntry[Index],
                        &FunctionTableEntry[Index + 1],
                        (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY32));

                    Wx86UserSpecialInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remove wx86 user special inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectUserPages(
                Wx86UserSpecialInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}
