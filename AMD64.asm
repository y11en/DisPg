;
;
; Copyright (c) 2015-2018 by blindtiger ( blindtiger@foxmail.com )
;
; The contents of this file are subject to the Mozilla Public License Version
; 2.0 (the "License"); you may not use this file except in compliance with
; the License. You may obtain a copy of the License at
; http://www.mozilla.org/MPL/
;
; Software distributed under the License is distributed on an "AS IS" basis,
; WITHOUT WARRANTY OF ANY KIND, either express or implied. SEe the License
; for the specific language governing rights and limitations under the
; License.
;
; The Initial Developer of the Original e is blindtiger.
;
;

    .XLIST
INCLUDE DEFS.INC
INCLUDE KSAMD64.INC
    .LIST

OPTION CASEMAP:NONE

IoGetInitialStack PROTO
PgDecodeClear PROTO

_DATA$00 SEGMENT PAGE 'DATA'

EhFrame struct
    P1Home dq ?                     ; parameter home addresses for
    P2Home dq ?                     ; called functions
    P3Home dq ?                     ;
    P4Home dq ?                     ;
    Context dq ?                    ; saved dispatcher context address
EhFrame ends

_DATA$00 ENDS

_TEXT$00 SEGMENT PAGE 'CODE'

ExceptionHandler :

    mov eax, ExceptionContinueSearch                            
    test dword ptr ErExceptionFlags[rcx], EXCEPTION_UNWIND      
    jnz @f       
    mov rax, EhFrame.Context[rdx]                               
    mov rax, DcEstablisherFrame[rax]                            
    mov DcEstablisherFrame[r9], rax                             
    mov eax, ExceptionNestedException                           

@@:   
    ret                                                         

PUBLIC ExceptionHandler

align 40h

ExecuteHandlerForException :

    sub rsp, (sizeof EhFrame)                                   

    mov EhFrame.Context[rsp], r9                                
    call qword ptr DcLanguageHandler [r9]                       
    nop                                                         
    add rsp, sizeof EhFrame                                     
    ret                                                         

PUBLIC ExecuteHandlerForException

align 40h

__NLG_Return :

    ret
    
PUBLIC __NLG_Return

align 40h

_NLG_Notify :

    mov [rsp + 8], rcx
    mov [rsp + 18h], rdx
    mov [rsp + 10h], r8d
    mov r9, 19930520h
    jmp __NLG_Return

PUBLIC _NLG_Notify

align 40h

RestoreProcessorControlState :

    mov rax, PsCr0 [rcx]                ; restore processor control registers
    mov cr0, rax                        ;
    mov rax, PsCr3 [rcx]                ;
    mov cr3, rax                        ;
    mov rax, PsCr4 [rcx]                ;
    mov cr4, rax                        ;
    mov rax, PsCr8 [rcx]                ;
    mov cr8, rax                        ;
    
    lgdt fword ptr PsGdtr [rcx]         ; restore GDTR
    lidt fword ptr PsIdtr [rcx]         ; restore IDTR

;
; Force the TSS descriptor into a non-busy state so no fault will occur when
; TR is loaded.
;

	movzx eax, word ptr PsTr [rcx]              ; get TSS selector
	add	rax, PsGdtr [rcx + 2]	                ; compute TSS GDT entry address
	and	byte ptr [rax + 5], NOT 2               ; clear busy bit
    ltr word ptr PsTr [rcx]                     ; restore TR

	xor eax, eax                                ; load a NULL selector into the ldt
	lldt ax

    ldmxcsr dword ptr PsMxCsr [rcx]             ; restore XMM control/status

;
; Restore debug control state.
;

    xor edx, edx                                ; restore debug registers
    mov dr7, rdx
    mov rax, PsKernelDr0 [rcx]
    mov rdx, PsKernelDr1 [rcx]
    mov dr0, rax
    mov dr1, rdx
    mov rax, PsKernelDr2 [rcx]
    mov rdx, PsKernelDr3 [rcx]
    mov dr2, rax
    mov dr3, rdx
    mov rdx, PsKernelDr7 [rcx]
    xor eax, eax
    mov dr6, rax
    mov dr7, rdx
    cmp byte ptr gs : [PcCpuVendor], CPU_AMD    ; check if AMD processor
    jne short KiRC30                            ; if ne, not authentic AMD processor

;
; The host processor is an authentic AMD processor.
;
; Check if branch tracing or last branch capture is enabled.
;

    test dx, DR7_TRACE_BRANCH                   ; test for trace branch enable
    jz short KiRC10                             ; if z, trace branch not enabled
    or eax, MSR_DEBUG_CRL_BTF                   ; set trace branch enable

KiRC10: 
    test dx, DR7_LAST_BRANCH                    ; test for last branch enable
    jz short KiRC20                             ; if z, last branch not enabled
    or eax, MSR_DEBUG_CTL_LBR                   ; set last branch enable

KiRC20: 
    test eax, eax                               ; test for extended debug enables
    jz short KiRC30                             ; if z, no extended debug enables
    mov r8d, eax                                ; save extended debug enables
    mov ecx, MSR_DEGUG_CTL                      ; set debug control MSR number
    rdmsr                                       ; set extended debug control
    and eax, not (MSR_DEBUG_CTL_LBR or MSR_DEBUG_CRL_BTF)
    or eax, r8d
    wrmsr

KiRC30: 
    ret                                         ; return

PUBLIC RestoreProcessorControlState

align 40h

SaveProcessorControlState :

    mov rax, cr0                                ; save processor control state
    mov PsCr0 [rcx], rax
    mov rax, cr2
    mov PsCr2 [rcx], rax
    mov rax, cr3
    mov PsCr3 [rcx], rax
    mov rax, cr4
    mov PsCr4 [rcx], rax
    mov rax, cr8
    mov PsCr8 [rcx], rax

    sgdt fword ptr PsGdtr [rcx]                 ; save GDTR
    sidt fword ptr PsIdtr [rcx]                 ; save IDTR
    
    str word ptr PsTr [rcx]                     ; save TR
    sldt word ptr PsLdtr [rcx]                  ; save LDTR
    
    stmxcsr dword ptr PsMxCsr [rcx]             ; save XMM control/status

;
; Save debug control state.
;

    mov rax, dr0                                ; save debug registers
    mov rdx, dr1
    mov PsKernelDr0 [rcx], rax
    mov PsKernelDr1 [rcx], rdx
    mov rax, dr2
    mov rdx, dr3
    mov PsKernelDr2 [rcx], rax
    mov PsKernelDr3 [rcx], rdx
    mov rax, dr6
    mov rdx, dr7
    mov PsKernelDr6 [rcx], rax
    mov PsKernelDr7 [rcx], rdx
    xor eax, eax
    mov dr7, rax
    cmp byte ptr gs : [PcCpuVendor], CPU_AMD    ; check if AMD processor
    jne short KiSC10                            ; if ne, not authentic AMD processor

;
; The host processor is an authentic AMD processor.
;
; Check if branch tracing or last branch capture is enabled.
;

    test dx, DR7_TRACE_BRANCH or DR7_LAST_BRANCH; test for extended enables
    jz short KiSC10                             ; if z, extended debugging not enabled
    mov r8, rcx                                 ; save processor state address
    mov ecx, MSR_LAST_BRANCH_FROM               ; save last branch information
    rdmsr
    mov PsLastBranchFromRip [r8], eax
    mov PsLastBranchFromRip [r8 + 4], edx
    mov ecx, MSR_LAST_BRANCH_TO
    rdmsr
    mov PsLastBranchToRip [r8], eax
    mov PsLastBranchToRip [r8 + 4], edx
    mov ecx, MSR_LAST_EXCEPTION_FROM
    rdmsr
    mov PsLastExceptionFromRip [r8], eax
    mov PsLastExceptionFromRip [r8 + 4], edx
    mov ecx, MSR_LAST_EXCEPTION_TO
    rdmsr
    mov PsLastExceptionToRip [r8], eax
    mov PsLastExceptionToRip [r8 + 4], edx
    mov ecx, MSR_DEGUG_CTL                      ; clear extended debug control
    rdmsr
    and eax, not (MSR_DEBUG_CTL_LBR or MSR_DEBUG_CRL_BTF)
    wrmsr

KiSC10: 
    ret                                         ; return

PUBLIC SaveProcessorControlState
        
align 40h

_btc64 :
    
    btc rcx, rdx
    mov rax, rcx
    ret

PUBLIC _btc64

align 40h

_PgEncodeClear :
    
extern PgEncodeClear : PROTO

    sub rsp, 28h
    
    call PgEncodeClear
    
    add rsp, 28h
    
    add rsp, 30h
    ret

PUBLIC _PgEncodeClear

align 40h

_RevertWorkerThreadToSelf :
    
extern NtosKiStartSystemThread : PTR
extern NtosPspSystemThreadStartup : PTR
extern NtosExpWorkerThread : PTR
extern NtosExpWorkerContext : PTR

    call PgDecodeClear

    call IoGetInitialStack

    mov rsp, rax
    sub rsp, KSTART_FRAME_LENGTH

    mov rax, NtosExpWorkerContext 
    mov SfP1Home [rsp], rax

    mov rax, NtosExpWorkerThread
    mov SfP2Home [rsp], rax

    mov rax, NtosPspSystemThreadStartup
    mov SfP3Home [rsp], rax
    
    xor rax, rax
    mov SfReturn [rsp], rax

    mov rax, NtosKiStartSystemThread
    jmp rax

PUBLIC _RevertWorkerThreadToSelf

align 40h

MakePgFire :

    sub rsp, 20h

    lea rcx, [rsp + 2]

    sidt fword ptr [rcx]

    mov ax, 0ffffh
    mov [rcx], ax

    lidt fword ptr [rcx]
    sidt fword ptr [rcx]

    add rsp, 20h

    ret

PUBLIC MakePgFire

align 40h

_TEXT$00 ENDS

END
