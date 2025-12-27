/*
 * WinHwBp - hardware breakpoint management library for x86/x64 Windows.
 * Copyright (c) 2025 houzeyhoo
 * SPDX-License-Identifier: MIT
 */

#ifndef WINHWBP_H
#define WINHWBP_H
#include <windows.h>

typedef enum _WINHWBP_SLOT
{
    WINHWBP_SLOT_0,
    WINHWBP_SLOT_1,
    WINHWBP_SLOT_2,
    WINHWBP_SLOT_3,
} WINHWBP_SLOT, *WINHWBP_PSLOT;

/* Represents the condition upon which a breakpoint is triggered. */
typedef enum _WINHWBP_COND
{
    WINHWBP_COND_EXECUTE,
    WINHWBP_COND_WRITE,
    /* 0x2 is unused */
    WINHWBP_COND_READ_WRITE = 0x3,
} WINHWBP_COND;

/* Represents the length of the breakpoint in bytes. */
typedef enum _WINHWBP_LEN
{
    WINHWBP_LEN_1,
    WINHWBP_LEN_2,
#if defined(_WIN64)
    /* x64 only */
    WINHWBP_LEN_8,
#endif
    WINHWBP_LEN_4 = 0x3,
} WINHWBP_LEN;

/* Represents user-configurable breakpoint information. */
typedef struct _WINHWBP_CONFIG
{
    /*
     * The address of the breakpoint.
     *
     * This value must be properly aligned depending on the `length` field. For example, if the `length` field is set
     * to `WINHWBP_LEN_4`, then `pAddress` must be aligned on a 4-byte boundary.
     */
    PVOID pAddress;
    WINHWBP_COND condition;
    WINHWBP_LEN length;
} WINHWBP_CONFIG, *WINHWBP_PCONFIG;

/* Represents complete breakpoint information. */
typedef struct _WINHWBP_INFO
{
    WINHWBP_CONFIG config;
    WINHWBP_SLOT slot;

    /* Whether the breakpoint is currently enabled. */
    BOOL bIsEnabled;

    /* Whether the breakpoint condition has been met. */
    BOOL bIsConditionMet;
} WINHWBP_INFO, *WINHWBP_PINFO;

/* Public error codes. */
typedef enum _WINHWBP_STATUS
{
    /* The operation completed successfully. */
    WINHWBP_STATUS_SUCCESS,

    /* One or more provided arguments are invalid. */
    WINHWBP_STATUS_INVALID_ARGUMENT,

    /* Failed to suspend the target thread. */
    WINHWBP_STATUS_SUSPEND_THREAD_FAILED,

    /* Failed to resume the target thread. */
    WINHWBP_STATUS_RESUME_THREAD_FAILED,

    /* Failed to retrieve the thread context. */
    WINHWBP_STATUS_GET_CONTEXT_FAILED,

    /* Failed to set the thread context. */
    WINHWBP_STATUS_SET_CONTEXT_FAILED,

    /* Could not find an available hardware breakpoint slot. */
    WINHWBP_STATUS_NO_AVAILABLE_SLOTS,
} WINHWBP_STATUS;

/*
 * Acquires the target thread context and calls `WinHwBp_Context_Get` on it.
 */
WINHWBP_STATUS WinHwBp_Get(_In_ HANDLE hThread, _In_ WINHWBP_SLOT slot, _Out_ WINHWBP_PINFO pInfo);

/*
 * Retrieves information about a hardware breakpoint.
 *
 * See `WINHWBP_INFO` for more information.
 */
WINHWBP_STATUS WinHwBp_Context_Get(_In_ const PCONTEXT pContext, _In_ WINHWBP_SLOT slot, _Out_ WINHWBP_PINFO pInfo);

/*
 * Acquires the target thread context and calls `WinHwBp_Context_Set` on it.
 */
WINHWBP_STATUS WinHwBp_Set(_In_ HANDLE hThread, _In_ WINHWBP_SLOT slot, _In_ WINHWBP_PCONFIG pConfig);

/*
 * Sets a hardware breakpoint. The set breakpoint is enabled by default.
 *
 * This is equivalent to calling `WinHwBp_Context_SetEx` with `bEnable` set to `TRUE`.
 *
 * See `WINHWBP_CONFIG` for more information.
 */
WINHWBP_STATUS WinHwBp_Context_Set(_Inout_ PCONTEXT pContext, _In_ WINHWBP_SLOT slot, _In_ WINHWBP_PCONFIG pConfig);

/*
 * Sets a hardware breakpoint.
 *
 * See `WINHWBP_CONFIG` for more information.
 */
WINHWBP_STATUS WinHwBp_Context_SetEx(_Inout_ PCONTEXT pContext, _In_ WINHWBP_SLOT slot, _In_ WINHWBP_PCONFIG pConfig,
                                     _In_ BOOL bEnable);

/*
 * Acquires the target thread context and calls `WinHwBp_Context_SetAuto` on it.
 */
WINHWBP_STATUS WinHwBp_SetAuto(_In_ HANDLE hThread, _In_ WINHWBP_PCONFIG pConfig, _Out_ WINHWBP_PSLOT pSlot);

/*
 * Sets a hardware breakpoint in the first available slot.
 *
 * A slot is considered available if it is not currently enabled.
 *
 * See `WINHWBP_CONFIG` for more information.
 */
WINHWBP_STATUS WinHwBp_Context_SetAuto(_Inout_ PCONTEXT pContext, _In_ WINHWBP_PCONFIG pConfig,
                                       _Out_ WINHWBP_PSLOT pSlot);

/*
 * Acquires the target thread context and calls `WinHwBp_Context_Clear` on it.
 */
WINHWBP_STATUS WinHwBp_Clear(_In_ HANDLE hThread, _In_ WINHWBP_SLOT slot);

/*
 * Zeroes out the specified hardware breakpoint.
 */
WINHWBP_STATUS WinHwBp_Context_Clear(_Inout_ PCONTEXT pContext, _In_ WINHWBP_SLOT slot);

/*
 * Zeroes out all hardware breakpoints.
 */
WINHWBP_STATUS WinHwBp_ClearAll(_In_ HANDLE hThread);

/*
 * Acquires the target thread context and calls `WinHwBp_Context_ClearAll` on it.
 */
WINHWBP_STATUS WinHwBp_Context_ClearAll(_Inout_ PCONTEXT pContext);

#endif /* WINHWBP_H */
