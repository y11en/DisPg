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

#include <OsDefs.h>
#include <StubsApi.h>

#include "Jump.h"
#include "Reload.h"
#include "Testis.h"
#include "Scan.h"

NTSTATUS
NTAPI
CopyStub(
    __in_opt PVOID BaseAddress,
    __in_bcount(BufferSize) CONST VOID * Buffer,
    __in SIZE_T BufferSize
);

ULONG
NTAPI
GetInstructionLength(
    __in PVOID ControlPc
)
{
    PCHAR TargetPc = NULL;
    LONG Extra = 0;
    ULONG Length = 0;

    __try {
        TargetPc = DetourCopyInstruction(
            NULL,
            NULL,
            ControlPc,
            NULL,
            &Extra);

        if (NULL != TargetPc) {
            Length += (ULONG)(TargetPc - ControlPc);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Length = 0;
    }

    return Length;
}

NTSTATUS
NTAPI
FindImageSpace(
    __in PVOID ImageBase,
    __in ULONG Characteristics,
    __in CCHAR Alignment,
    __out PVOID * JumpAddress
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    PCHAR ControlPc = NULL;
    PVOID EndOfSection = NULL;
    SHORT Index = 0;

    NtHeaders = RtlImageNtHeader(ImageBase);

    if (FALSE != MmIsAddressValid(NtHeaders)) {
        NtSection = IMAGE_FIRST_SECTION(NtHeaders);

        Status = STATUS_NO_MEMORY;

        for (Index = NtHeaders->FileHeader.NumberOfSections - 1;
            Index >= 0;
            Index--) {
            if (0 != NtSection[Index].VirtualAddress) {
                SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                SizeToLock = max(
                    NtSection[Index].SizeOfRawData,
                    NtSection[Index].Misc.VirtualSize);

                if (FALSE != MmIsAddressValid(SectionBase)) {
                    if (Characteristics == FlagOn(
                        NtSection[Index].Characteristics,
                        Characteristics)) {
                        EndOfSection = SectionBase +
                            AlignedToSize(
                                SizeToLock,
                                NtHeaders->OptionalHeader.SectionAlignment);

                        ControlPc = SectionBase + AlignedToSize(SizeToLock, 8);

                    retry:
                        if ((ULONG_PTR)ControlPc <= (ULONG_PTR)EndOfSection - Alignment) {
                            if (FIELD_OFFSET(JMPCODE, u1) == RtlCompareMemory(
                                ControlPc,
                                JUMP_CODE,
                                FIELD_OFFSET(JMPCODE, u1))) {
                                ControlPc = (PCHAR)ControlPc + Alignment;

                                goto retry;
                            }
                            else {
                                if (NULL != JumpAddress) {
                                    *JumpAddress = ControlPc;
                                }

                                Status = STATUS_SUCCESS;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        Status = STATUS_IMAGE_CHECKSUM_MISMATCH;
    }

    return Status;
}

NTSTATUS
NTAPI
BuildJumpCode(
    __in PVOID Function,
    __inout PVOID * NewAddress
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PHYSICAL_ADDRESS PhysicalAddress = { 0 };
    PVOID VirtualAddress = NULL;
    PJMPCODE JmpCode = NULL;

    JmpCode = ExAllocatePool(
        NonPagedPool,
        sizeof(JMPCODE));

    if (NULL != JmpCode) {
        RtlFillMemory(
            JmpCode,
            sizeof(JMPCODE),
            0xcc);

        RtlCopyMemory(
            JmpCode,
            JUMP_CODE,
            sizeof(JUMP_CODE) - 1);

        RtlCopyMemory(
            &JmpCode->u1,
            &Function,
            sizeof(ULONG_PTR));

        Status = CopyStub(
            *NewAddress,
            JmpCode,
            FIELD_OFFSET(JMPCODE, Filler));

        ExFreePool(JmpCode);
    }
    else {
        Status = STATUS_NO_MEMORY;
    }

    return Status;
}

NTSTATUS
NTAPI
SetVaildJump(
    __in PVOID Function,
    __in PVOID ImageBase,
    __inout PVOID * NewAddress
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Status = FindImageSpace(
        ImageBase,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
        sizeof(JMPCODE),
        NewAddress);

    if (NT_SUCCESS(Status)) {
        Status = BuildJumpCode(
            Function,
            NewAddress);
    }

    return Status;
}

PVOID
NTAPI
BuildShadowJump(
    __in PVOID Function,
    __in PVOID NewEntry
)
{
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    LONG Extra = 0;
    ULONG Length = 0;
    ULONG TotalLength = 0;
    PCHAR Dst = NULL;
    PCHAR DstEnd = NULL;
    PCHAR DstPool = NULL;

    TargetPc = Function;

    while (TRUE) {
        ControlPc = TargetPc;

        TargetPc = DetourCopyInstruction(
            NULL,
            NULL,
            ControlPc,
            NULL,
            &Extra);

        Length += (ULONG)((TargetPc - ControlPc) + Extra);

        if ((ULONG_PTR)TargetPc -
            (ULONG_PTR)Function >= sizeof(JMPCODE)) {
            TotalLength = Length + sizeof(JMPCODE);

            Dst = ExAllocatePool(
                NonPagedPool,
                TotalLength);

            if (NULL != Dst) {
                DstPool = Dst;
                DstEnd = Dst + Length;

                BuildJumpCode(
                    TargetPc,
                    &DstEnd);

                TargetPc = Function;

                while (TRUE) {
                    ControlPc = TargetPc;

                    TargetPc = DetourCopyInstruction(
                        Dst,
                        &DstEnd,
                        ControlPc,
                        NULL,
                        &Extra);

                    Dst += (TargetPc - ControlPc) + Extra;

                    if (Dst == DstEnd) {
                        BuildJumpCode(
                            NewEntry,
                            &Function);

                        break;
                    }
                }
            }

            break;
        }
    }

    return DstPool;
}

BOOLEAN
NTAPI
EnableDynamicCode(
    __in PEPROCESS Process,
    __in BOOLEAN State
)
{
    BOOLEAN OldState = FALSE;
    HANDLE UniqueProcess = NULL;
    PMITIGATIONFLAGS MitigationFlags = NULL;
    ULONG Index = 0;

    UniqueProcess = PsGetProcessId(Process);

    if (OsBuildNumber >= 9600 &&
        OsBuildNumber < 15063) {
        for (Index = 0;
            Index < PAGE_SIZE;
            Index += sizeof(PVOID)) {
            if (*(PHANDLE)((PCHAR)Process + Index) == UniqueProcess) {
                MitigationFlags = (PCHAR)Process +
                    Index +
                    sizeof(LIST_ENTRY) +
                    sizeof(HANDLE);

                OldState = MitigationFlags->s1.DisableDynamicCode;
                MitigationFlags->s1.DisableDynamicCode = State;
                break;
            }
        }
    }
    else if (OsBuildNumber >= 15063 &&
        OsBuildNumber < 16299) {
        for (Index = 0;
            Index < PAGE_SIZE;
            Index += sizeof(PVOID)) {
            if (*(PHANDLE)((PCHAR)Process + Index) == UniqueProcess) {
                MitigationFlags = (PCHAR)Process +
                    Index +
                    sizeof(LIST_ENTRY) +
                    sizeof(HANDLE) +
                    sizeof(HANDLE);

                OldState = MitigationFlags->s1.DisableDynamicCode;
                MitigationFlags->s1.DisableDynamicCode = State;
                break;
            }
        }
    }
    else if (OsBuildNumber >= 16299 &&
        OsBuildNumber < 17134) {
#ifndef _WIN64
        MitigationFlags = (PCHAR)Process + 0x3d8;
#else
        MitigationFlags = (PCHAR)Process + 0x828;
#endif // !_WIN64

        OldState = MitigationFlags->s1.DisableDynamicCode;
        MitigationFlags->s2.DisableDynamicCode = State;
    }
    else if (OsBuildNumber >= 17134) {
#ifndef _WIN64
        MitigationFlags = (PCHAR)Process + 0x3e0;
#else
        MitigationFlags = (PCHAR)Process + 0x828;
#endif // !_WIN64

        OldState = MitigationFlags->s1.DisableDynamicCode;
        MitigationFlags->s2.DisableDynamicCode = State;
    }

    return OldState;
}
