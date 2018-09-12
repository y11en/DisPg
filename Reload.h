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

#ifndef _RELOAD_H_
#define _RELOAD_H_

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

    typedef struct _REPLACE_THUNK {
        PSTR Name;
        USHORT Ordinal;
        PSTR ReplaceName;
        USHORT ReplaceOrdinal;
        PVOID Function;
    } REPLACE_THUNK, *PREPLACE_THUNK;

    VOID
        NTAPI
        InitializeImageList(
            VOID
        );

    NTSTATUS
        NTAPI
        FindEntryForAllKernelImage(
            __in PSTR ImageName,
            __out PKLDR_DATA_TABLE_ENTRY * DataTableEntry
        );

    NTSTATUS
        NTAPI
        FindEntryForAllUserImage(
            __in PSTR ImageName,
            __out PLDR_DATA_TABLE_ENTRY * DataTableEntry
        );

    NTSTATUS
        NTAPI
        FindEntryForAllImage(
            __in PSTR ImageName,
            __out PVOID * DataTableEntry
        );

    NTSTATUS
        NTAPI
        FindEntryForAllKernelAddress(
            __in PVOID Address,
            __out PKLDR_DATA_TABLE_ENTRY * DataTableEntry
        );

    NTSTATUS
        NTAPI
        FindEntryForAllUserAddress(
            __in PVOID Address,
            __out PLDR_DATA_TABLE_ENTRY * DataTableEntry
        );

    NTSTATUS
        NTAPI
        FindEntryForAllAddress(
            __in PVOID Address,
            __out PVOID * DataTableEntry
        );

    PVOID
        NTAPI
        GetImageHandle(
            __in PSTR ImageName
        );

    PVOID
        NTAPI
        GetAddressOfEntryPoint(
            __in PVOID ImageBase
        );

    ULONG
        NTAPI
        GetSizeOfImage(
            __in PVOID ImageBase
        );

    PIMAGE_SECTION_HEADER
        NTAPI
        SectionTableFromVirtualAddress(
            __in PVOID ImageBase,
            __in PVOID Address
        );

    PVOID
        NTAPI
        GetProcedureAddress(
            __in PVOID ImageBase,
            __in_opt PSTR ProcedureName,
            __in_opt ULONG ProcedureNumber
        );

    PULONG_PTR
        NTAPI
        FindThunk(
            __in PVOID ImageBase,
            __in PSTR ImportName,
            __in_opt PSTR ThunkName,
            __in_opt ULONG ThunkNumber
        );

    VOID
        NTAPI
        ReplaceThunk(
            __in PVOID ImageBase,
            __in PSTR ImportName,
            __in PREPLACE_THUNK ThunkTable,
            __in_bcount(ThunkTable) ULONG ThunkCount
        );

    VOID
        NTAPI
        RelocateImage(
            __in PVOID ImageBase,
            __in LONG_PTR Diff
        );

    PKLDR_DATA_TABLE_ENTRY
        NTAPI
        InsertNoImageList(
            __in PCWSTR ImageName,
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        LoadNoImage(
            __in PVOID ViewBase,
            __out_opt PVOID * ImageBase
        );

    VOID
        NTAPI
        RemoveNoImageList(
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        UnloadNoImage(
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        SetUserImageProtection(
            __in PVOID ImageBase,
            __in BOOLEAN Reset
        );

    PLDR_DATA_TABLE_ENTRY
        NTAPI
        NotificationRegister(
            __in PCWSTR ImageName,
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        LoadUserNoImage(
            __in PVOID ViewBase,
            __out_opt PVOID * ImageBase
        );

    VOID
        NTAPI
        NotificationUnregister(
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        UnloadUserNoImage(
            __in PVOID ImageBase
        );

#ifdef _WIN64
    NTSTATUS
        NTAPI
        Wx86FindEntryForAllUserImage(
            __in PSTR ImageName,
            __out PLDR_DATA_TABLE_ENTRY32 * DataTableEntry
        );

    NTSTATUS
        NTAPI
        Wx86FindEntryForAllUserAddress(
            __in PVOID Address,
            __out PLDR_DATA_TABLE_ENTRY32 * DataTableEntry
        );

    ULONG
        NTAPI
        Wx86GetImageHandle(
            __in PSTR ImageName
        );

    ULONG
        NTAPI
        Wx86GetProcedureAddress(
            __in ULONG ImageBase,
            __in_opt PSTR ProcedureName,
            __in_opt ULONG ProcedureNumber
        );

    PKLDR_DATA_TABLE_ENTRY32
        NTAPI
        Wx86NotificationRegister(
            __in PCWSTR ImageName,
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        Wx86LoadUserNoImage(
            __in PVOID ViewBase,
            __out PVOID * ImageBase
        );

    VOID
        NTAPI
        Wx86NotificationUnregister(
            __in PVOID ImageBase
        );
#endif // _WIN64

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_RELOAD_H_
