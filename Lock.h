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

#ifndef _LOCK_H_
#define _LOCK_H_

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

    typedef LONG EX_SPIN_LOCK, *PEX_SPIN_LOCK;

    NTKERNELAPI
        KIRQL
        NTAPI
        ExAcquireSpinLockShared(
            __inout PEX_SPIN_LOCK SpinLock
        );

    NTKERNELAPI
        VOID
        NTAPI
        ExReleaseSpinLockShared(
            __inout PEX_SPIN_LOCK SpinLock,
            __in KIRQL OldIrql
        );

    NTKERNELAPI
        VOID
        NTAPI
        ExAcquireSpinLockSharedAtDpcLevel(
            __inout PEX_SPIN_LOCK SpinLock
        );

    NTKERNELAPI
        VOID
        NTAPI
        ExReleaseSpinLockSharedFromDpcLevel(
            __inout PEX_SPIN_LOCK SpinLock
        );

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_LOCK_H_
