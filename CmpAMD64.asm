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

_DATA$00 SEGMENT PAGE 'DATA'

_DATA$00 ENDS

_TEXT$00 SEGMENT PAGE 'CODE'

CmpByte :

    cmp cl, dl
    setnz al
    ret

PUBLIC CmpByte

align 40h

CmpShort :

    cmp cx, dx
    setnz al
    ret

PUBLIC CmpShort

align 40h

CmpLong :

    cmp ecx, edx
    setnz al
    ret

PUBLIC CmpLong

align 40h

CmpLongLong :

    cmp rcx, rdx
    setnz al
    ret

PUBLIC CmpLongLong

align 40h

_TEXT$00 ENDS

END
