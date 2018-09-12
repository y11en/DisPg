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

#include "Ctx.h"
#include "Reload.h"
#include "Stack.h"
#include "Testis.h"

PSTR
NTAPI
FindSymbol(
    __in PVOID Address,
    __out_opt PKLDR_DATA_TABLE_ENTRY * DataTableEntry
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PKLDR_DATA_TABLE_ENTRY FoundDataTableEntry = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    ULONG Size = 0;
    PULONG NameTable = NULL;
    PUSHORT OrdinalTable = NULL;
    PULONG AddressTable = NULL;
    USHORT HintIndex = 0;
    PVOID ProcedureAddress = NULL;
    PVOID NearAddress = NULL;
    PSTR ProcedureName = NULL;

    Status = FindEntryForAllKernelAddress(
        Address,
        &FoundDataTableEntry);

    if (Status >= 0) {
        ExportDirectory = RtlImageDirectoryEntryToData(
            FoundDataTableEntry->DllBase,
            TRUE,
            IMAGE_DIRECTORY_ENTRY_EXPORT,
            &Size);

        if (NULL != ExportDirectory) {
            NameTable = (PCHAR)FoundDataTableEntry->DllBase + ExportDirectory->AddressOfNames;
            OrdinalTable = (PCHAR)FoundDataTableEntry->DllBase + ExportDirectory->AddressOfNameOrdinals;
            AddressTable = (PCHAR)FoundDataTableEntry->DllBase + ExportDirectory->AddressOfFunctions;

            if (NULL != NameTable &&
                NULL != OrdinalTable &&
                NULL != AddressTable) {
                for (HintIndex = 0;
                    HintIndex < ExportDirectory->NumberOfNames;
                    HintIndex++) {
                    ProcedureAddress = (PCHAR)FoundDataTableEntry->DllBase + AddressTable[OrdinalTable[HintIndex]];

                    if ((ULONG_PTR)ProcedureAddress <=
                        (ULONG_PTR)Address) {
                        if (NULL == NearAddress) {
                            NearAddress = ProcedureAddress;
                            ProcedureName = (PCHAR)FoundDataTableEntry->DllBase + NameTable[HintIndex];
                        }
                        else if ((ULONG_PTR)ProcedureAddress > (ULONG_PTR)NearAddress) {
                            NearAddress = ProcedureAddress;
                            ProcedureName = (PCHAR)FoundDataTableEntry->DllBase + NameTable[HintIndex];
                        }
                    }
                }
            }
        }

        if (NULL != DataTableEntry) {
            *DataTableEntry = FoundDataTableEntry;
        }
    }
    else {
        if (NULL != DataTableEntry) {
            *DataTableEntry = NULL;
        }
    }

    return ProcedureName;
}

VOID
NTAPI
PrintSymbol(
    __in PVOID Address
)
{
    PKLDR_DATA_TABLE_ENTRY DataTableEnry = NULL;
    PVOID ProcedureAddress = NULL;
    PSTR ProcedureName = NULL;

    ProcedureName = FindSymbol(
        (PVOID)Address,
        &DataTableEnry);

    if (NULL != ProcedureName) {
        ProcedureAddress = GetProcedureAddress(
            DataTableEnry->DllBase,
            ProcedureName,
            0);

        if (0 == (ULONG64)Address - (ULONG64)ProcedureAddress) {
#ifndef VMP
            DbgPrint(
                "Soul - Testis - < %p > < %wZ!%hs >\n",
                Address,
                &DataTableEnry->BaseDllName,
                ProcedureName);
#endif // !VMP
        }
        else {
#ifndef VMP
            DbgPrint(
                "Soul - Testis - < %p > < %wZ!%hs + 0x%x >\n",
                Address,
                &DataTableEnry->BaseDllName,
                ProcedureName,
                (ULONG64)Address - (ULONG64)ProcedureAddress);
#endif // !VMP
        }
    }
    else if (NULL != DataTableEnry) {
#ifndef VMP
        DbgPrint(
            "Soul - Testis - < %p > < %wZ!%s + 0x%x >\n",
            Address,
            &DataTableEnry->BaseDllName,
            (ULONG64)Address - (ULONG64)DataTableEnry->DllBase);
#endif // !VMP
    }
    else {
#ifndef VMP
        DbgPrint(
            "Soul - Testis - < %p >\n",
            Address);
#endif // !VMP
    }
}

PKTRAP_FRAME
NTAPI
GetBaseTrapFrame(
    __in PETHREAD Thread
)
{
#ifndef _WIN64
    ULONG InitialStack = 0;

    InitialStack = (ULONG)IoGetInitialStack();

    if (OsBuildNumber < 9200) {
        return (PKTRAP_FRAME)(InitialStack - \
            PSPALIGN_UP(sizeof(KTRAP_FRAME), KTRAP_FRAME_ALIGN) - \
            sizeof(FX_SAVE_AREA));
    }
    else {
        return (PKTRAP_FRAME)(InitialStack - \
            PSPALIGN_UP(sizeof(KTRAP_FRAME), KTRAP_FRAME_ALIGN));
    }
#else
    ULONG64 InitialStack = 0;
    PKSTACK_CONTROL_SPECIAL StackControlSpecial = NULL;
    PKSTACK_CONTROL StackControl = NULL;

    InitialStack = (ULONG64)IoGetInitialStack();

    if (OsBuildNumber < 9200) {
        StackControlSpecial = (PKSTACK_CONTROL_SPECIAL)InitialStack;

        while (StackControlSpecial->Previous.StackBase != 0) {
            InitialStack = StackControlSpecial->Previous.InitialStack;
            StackControlSpecial = (PKERNEL_STACK_CONTROL)InitialStack;
        }
    }
    else {
        StackControl = (PKSTACK_CONTROL)InitialStack;

        while (StackControl->Previous.StackBase != 0) {
            InitialStack = StackControl->Previous.InitialStack;
            StackControl = (PKSTACK_CONTROL)InitialStack;
        }
    }

    return (PKTRAP_FRAME)(InitialStack - KTRAP_FRAME_LENGTH);
#endif // !_WIN64
}

VOID
NTAPI
PrintFrameChain(
    __in_opt ULONG FramesToSkip
)
{
    ULONG Index = 0;
    ULONG Count = 0;
    CALLERS Callers[MAX_STACK_DEPTH] = { 0 };

    Count = WalkFrameChain(
        Callers,
        MAX_STACK_DEPTH);

    for (Index = FramesToSkip;
        Index < Count;
        Index++) {
        PrintSymbol(Callers[Index].Establisher);
    }
}
