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

#ifndef _JUMP_H_
#define _JUMP_H_

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

#ifndef RVA_TO_VA
#define RVA_TO_VA(p) ((PVOID)((PCHAR)(p) + *(PLONG)(p) + sizeof(LONG)))
#endif // !RVA_TO_VA

#define JUMP_CODE32 "\x68\xff\xff\xff\xff\xc3"
#define JUMP_CODE64 "\xff\x25\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"

#define JUMP_CODE32_LENGTH (sizeof(JUMP_CODE32) - 1)
#define JUMP_CODE64_LENGTH (sizeof(JUMP_CODE64) - 1)

    typedef struct _JMPCODE32 {
#pragma pack(push, 1)
        UCHAR Reserved1[1];
        union {
            UCHAR Reserved2[4];
            LONG JumpAddress;
        }u1;

        UCHAR Reserved3[1];
        UCHAR Filler[2];
#pragma pack(pop)
    }JMPCODE32, *PJMPCODE32;

    C_ASSERT(FIELD_OFFSET(JMPCODE32, u1.JumpAddress) == 1);
    C_ASSERT(sizeof(JMPCODE32) == 8);

    typedef struct _JMPCODE64 {
#pragma pack(push, 1)
        UCHAR Reserved1[6];

        union {
            UCHAR Reserved2[8];
            LONGLONG JumpAddress;
        }u1;

        UCHAR Filler[2];
#pragma pack(pop)
    }JMPCODE64, *PJMPCODE64;

    C_ASSERT(FIELD_OFFSET(JMPCODE64, u1.JumpAddress) == 6);
    C_ASSERT(sizeof(JMPCODE64) == 0x10);

#ifndef _WIN64
#define JUMP_CODE JUMP_CODE32 
    typedef JMPCODE32 JMPCODE;
    typedef JMPCODE32 *PJMPCODE;
#else
#define JUMP_CODE JUMP_CODE64
    typedef JMPCODE64 JMPCODE;
    typedef JMPCODE64 *PJMPCODE;
#endif // !_WIN64

    typedef union _MITIGATIONFLAGS {
        ULONG MitigationFlags;

        struct {
            BOOLEAN JobNotReallyActive : 1;
            BOOLEAN AccountingFolded : 1;
            BOOLEAN NewProcessReported : 1;
            BOOLEAN ExitProcessReported : 1;
            BOOLEAN ReportCommitChanges : 1;
            BOOLEAN LastReportMemory : 1;
            BOOLEAN ForceWakeCharge : 1;
            BOOLEAN CrossSessionCreate : 1;
            BOOLEAN NeedsHandleRundown : 1;
            BOOLEAN RefTraceEnabled : 1;
            BOOLEAN DisableDynamicCode : 1;
            BOOLEAN EmptyJobEvaluated : 1;
            BOOLEAN DefaultPagePriority : 3;
            BOOLEAN PrimaryTokenFrozen : 1;
            BOOLEAN ProcessVerifierTarget : 1;
            BOOLEAN StackRandomizationDisabled : 1;
            BOOLEAN AffinityPermanent : 1;
            BOOLEAN AffinityUpdateEnable : 1;
            BOOLEAN PropagateNode : 1;
            BOOLEAN ExplicitAffinity : 1;
            BOOLEAN ProcessExecutionState : 2;
            BOOLEAN DisallowStrippedImages : 1;
            BOOLEAN HighEntropyASLREnabled : 1;
            BOOLEAN ExtensionPointDisable : 1;
            BOOLEAN ForceRelocateImages : 1;
            BOOLEAN ProcessStateChangeRequest : 2;
            BOOLEAN ProcessStateChangeInProgress : 1;
            BOOLEAN DisallowWin32kSystemCalls : 1;
        }s1;

        struct {
            BOOLEAN ControlFlowGuardEnabled : 1;
            BOOLEAN ControlFlowGuardExportSuppressionEnabled : 1;
            BOOLEAN ControlFlowGuardStrict : 1;
            BOOLEAN DisallowStrippedImages : 1;
            BOOLEAN ForceRelocateImages : 1;
            BOOLEAN HighEntropyASLREnabled : 1;
            BOOLEAN StackRandomizationDisabled : 1;
            BOOLEAN ExtensionPointDisable : 1;
            BOOLEAN DisableDynamicCode : 1;
            BOOLEAN DisableDynamicCodeAllowOptOut : 1;
            BOOLEAN DisableDynamicCodeAllowRemoteDowngrade : 1;
            BOOLEAN AuditDisableDynamicCode : 1;
            BOOLEAN DisallowWin32kSystemCalls : 1;
            BOOLEAN AuditDisallowWin32kSystemCalls : 1;
            BOOLEAN EnableFilteredWin32kAPIs : 1;
            BOOLEAN AuditFilteredWin32kAPIs : 1;
            BOOLEAN DisableNonSystemFonts : 1;
            BOOLEAN AuditNonSystemFontLoading : 1;
            BOOLEAN PreferSystem32Images : 1;
            BOOLEAN ProhibitRemoteImageMap : 1;
            BOOLEAN AuditProhibitRemoteImageMap : 1;
            BOOLEAN ProhibitLowILImageMap : 1;
            BOOLEAN AuditProhibitLowILImageMap : 1;
            BOOLEAN SignatureMitigationOptIn : 1;
            BOOLEAN AuditBlockNonMicrosoftBinaries : 1;
            BOOLEAN AuditBlockNonMicrosoftBinariesAllowStore : 1;
            BOOLEAN LoaderIntegrityContinuityEnabled : 1;
            BOOLEAN AuditLoaderIntegrityContinuity : 1;
            BOOLEAN EnableModuleTamperingProtection : 1;
            BOOLEAN EnableModuleTamperingProtectionNoInherit : 1;
            BOOLEAN RestrictIndirectBranchPrediction : 1;
        }s2;
    }MITIGATIONFLAGS, *PMITIGATIONFLAGS;

    PVOID
        NTAPI
        DetourCopyInstruction(
            __in_opt PVOID Dst,
            __in_opt PVOID * DstPool,
            __in PVOID Src,
            __in_opt PVOID * Target,
            __in LONG * Extra
        );

    ULONG
        NTAPI
        GetInstructionLength(
            __in PVOID Address
        );

    NTSTATUS
        NTAPI
        FindImageSpace(
            __in PVOID ImageBase,
            __in ULONG Characteristics,
            __in CCHAR Alignment,
            __out PVOID * JumpAddress
        );

    NTSTATUS
        NTAPI
        BuildJumpCode(
            __in PVOID Function,
            __inout PVOID * NewAddress
        );

    NTSTATUS
        NTAPI
        SetVaildJump(
            __in PVOID Function,
            __in PVOID DllBase,
            __inout PVOID * NewAddress
        );

    PVOID
        NTAPI
        BuildShadowJump(
            __in PVOID Function,
            __in PVOID NewEntry
        );

    BOOLEAN
        NTAPI
        EnableDynamicCode(
            __in PEPROCESS Process,
            __in BOOLEAN State
        );

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_JUMP_H_
