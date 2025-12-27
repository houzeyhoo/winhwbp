/*
 * WinHwBp - hardware breakpoint management library for x86/x64 Windows.
 * Copyright (c) 2025 houzeyhoo
 * SPDX-License-Identifier: MIT
 */

#include <winhwbp.h>
#include "drx.h"
#include <assert.h>

typedef enum _WINHWBP_OP
{
    WINHWBP_OP_GET,
    WINHWBP_OP_SET,
    WINHWBP_OP_SET_AUTO,
    WINHWBP_OP_CLEAR,
    WINHWBP_OP_CLEAR_ALL,
} WINHWBP_OP;

typedef union _WINHWBP_OP_ARGS {
    struct
    {
        WINHWBP_SLOT slot;
        WINHWBP_PINFO pInfo;
    } get;

    struct
    {
        WINHWBP_SLOT slot;
        WINHWBP_PCONFIG pConfig;
    } set;

    struct
    {
        WINHWBP_PCONFIG pConfig;
        WINHWBP_PSLOT pSlot;
    } setAuto;

    struct
    {
        WINHWBP_SLOT slot;
    } clear;

    /* clearAll doesn't take any arguments */
} WINHWBP_OP_ARGS, *WINHWBP_POP_ARGS;

static BOOL IsValidConfig(const WINHWBP_PCONFIG pConfig)
{
    if (!pConfig)
    {
        return FALSE;
    }

    /* Condition must be 0 (execute), 1 (read) or 3 (read write) */
    if (pConfig->condition < WINHWBP_COND_EXECUTE || pConfig->condition > WINHWBP_COND_READ_WRITE ||
        pConfig->condition == 2)
    {
        return FALSE;
    }

    /* Length must be within 0-3 range, where 0=1, 1=2, 2=8, 3=4 */
    if (pConfig->length < WINHWBP_LEN_1 || pConfig->length > WINHWBP_LEN_4)
    {
        return FALSE;
    }
#if !defined(_WIN64)
    /* On x86, length 8 is invalid */
    if (pConfig->length == 2)
    {
        return FALSE;
    }
#endif

    /* Execute condition requires length to be set to 1 */
    if (pConfig->condition == WINHWBP_COND_EXECUTE && pConfig->length != WINHWBP_LEN_1)
    {
        return FALSE;
    }

    /* Address must be aligned according to breakpoint length */
    SIZE_T mask = 0;
    switch (pConfig->length)
    {
    case WINHWBP_LEN_1:
        mask = 0x0;
        break;
    case WINHWBP_LEN_2:
        mask = 0x1;
        break;
    case WINHWBP_LEN_4:
        mask = 0x3;
        break;
#if defined(_WIN64)
    case WINHWBP_LEN_8:
        mask = 0x7;
        break;
#endif
    }
    return (((SIZE_T)(pConfig->pAddress) & mask) == 0);
}

static WINHWBP_STATUS ExecuteOperation(HANDLE hThread, WINHWBP_OP operation, WINHWBP_POP_ARGS pArgs)
{
    assert(operation >= WINHWBP_OP_GET && operation <= WINHWBP_OP_CLEAR_ALL);
    /* ClearAll doesn't require arguments, so NULL is expected. Other operations do, though */
    assert(pArgs || operation == WINHWBP_OP_CLEAR_ALL);

    if (!hThread || hThread == INVALID_HANDLE_VALUE)
    {
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }

    /* Don't suspend the current thread */
    if (GetThreadId(hThread) == GetCurrentThreadId())
    {
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }

    if (SuspendThread(hThread) == (DWORD)-1)
    {
        return WINHWBP_STATUS_SUSPEND_THREAD_FAILED;
    }

    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &context))
    {
        ResumeThread(hThread);
        return WINHWBP_STATUS_GET_CONTEXT_FAILED;
    }

    WINHWBP_STATUS status = WINHWBP_STATUS_SUCCESS;
    switch (operation)
    {
    case WINHWBP_OP_GET:
        status = WinHwBp_Context_Get(&context, pArgs->get.slot, pArgs->get.pInfo);
        break;
    case WINHWBP_OP_SET:
        status = WinHwBp_Context_Set(&context, pArgs->set.slot, pArgs->set.pConfig);
        break;
    case WINHWBP_OP_SET_AUTO:
        status = WinHwBp_Context_SetAuto(&context, pArgs->setAuto.pConfig, pArgs->setAuto.pSlot);
        break;
    case WINHWBP_OP_CLEAR:
        status = WinHwBp_Context_Clear(&context, pArgs->clear.slot);
        break;
    case WINHWBP_OP_CLEAR_ALL:
        status = WinHwBp_Context_ClearAll(&context);
        break;
    }

    BOOL bIsMutatingOp = operation != WINHWBP_OP_GET;

    /* Only write the context if the operation actually succeeds (and needs it) */
    if (bIsMutatingOp && status == WINHWBP_STATUS_SUCCESS)
    {
        if (!SetThreadContext(hThread, &context))
        {
            status = WINHWBP_STATUS_SET_CONTEXT_FAILED;
        }
    }

    if (ResumeThread(hThread) == (DWORD)-1)
    {
        /*
         * If resuming the thread fails, override the status to indicate this. This potentially shadows other errors
         * (e.g., invalid arguments), but it's probably more important to inform the caller that their thread is stuck
         * as suspended.
         */
        status = WINHWBP_STATUS_RESUME_THREAD_FAILED;
    }
    return status;
}

WINHWBP_STATUS WinHwBp_Get(_In_ HANDLE hThread, _In_ WINHWBP_SLOT slot, _Out_ WINHWBP_PINFO pInfo)
{
    WINHWBP_OP_ARGS args = {0};
    args.get.slot = slot;
    args.get.pInfo = pInfo;
    return ExecuteOperation(hThread, WINHWBP_OP_GET, &args);
}

WINHWBP_STATUS WinHwBp_Context_Get(_In_ const PCONTEXT pContext, _In_ WINHWBP_SLOT slot, _Out_ WINHWBP_PINFO pInfo)
{
    if (!pContext || !pInfo)
    {
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }

    ZeroMemory(pInfo, sizeof(*pInfo));

    switch (slot)
    {
    case WINHWBP_SLOT_0:
        pInfo->config.pAddress = (PVOID)(pContext->Dr0);
        break;
    case WINHWBP_SLOT_1:
        pInfo->config.pAddress = (PVOID)(pContext->Dr1);
        break;
    case WINHWBP_SLOT_2:
        pInfo->config.pAddress = (PVOID)(pContext->Dr2);
        break;
    case WINHWBP_SLOT_3:
        pInfo->config.pAddress = (PVOID)(pContext->Dr3);
        break;
    default:
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }
    pInfo->slot = slot;

    pInfo->config.condition = (WINHWBP_COND)((pContext->Dr7 & DR7_COND_MASK(slot)) >> DR7_COND_POS(slot));
    pInfo->config.length = (WINHWBP_LEN)((pContext->Dr7 & DR7_LEN_MASK(slot)) >> DR7_LEN_POS(slot));

    /*
     * Since Windows doesn't use hardware TSS, the local and global enable bits should be functionally equivalent. We
     * prefer using local enable bits, but check for both here in case another tool set a breakpoint using the global
     * enable bit.
     */
    pInfo->bIsEnabled = ((pContext->Dr7 & DR7_LE_MASK(slot)) != 0) || ((pContext->Dr7 & DR7_GE_MASK(slot)) != 0);
    pInfo->bIsConditionMet = (pContext->Dr6 & DR6_BC_MASK(slot)) != 0;
    return WINHWBP_STATUS_SUCCESS;
}

WINHWBP_STATUS WinHwBp_Set(_In_ HANDLE hThread, _In_ WINHWBP_SLOT slot, _In_ WINHWBP_PCONFIG pConfig)
{
    WINHWBP_OP_ARGS args = {0};
    args.set.slot = slot;
    args.set.pConfig = pConfig;
    return ExecuteOperation(hThread, WINHWBP_OP_SET, &args);
}

WINHWBP_STATUS WinHwBp_Context_Set(_Inout_ PCONTEXT pContext, _In_ WINHWBP_SLOT slot, _In_ WINHWBP_PCONFIG pConfig)
{
    return WinHwBp_Context_SetEx(pContext, slot, pConfig, TRUE);
}

WINHWBP_STATUS WinHwBp_Context_SetEx(_Inout_ PCONTEXT pContext, _In_ WINHWBP_SLOT slot, _In_ WINHWBP_PCONFIG pConfig,
                                     _In_ BOOL bEnable)
{
    if (!pContext || !IsValidConfig(pConfig))
    {
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }

    switch (slot)
    {
    case WINHWBP_SLOT_0:
        pContext->Dr0 = (DWORD_PTR)(pConfig->pAddress);
        break;
    case WINHWBP_SLOT_1:
        pContext->Dr1 = (DWORD_PTR)(pConfig->pAddress);
        break;
    case WINHWBP_SLOT_2:
        pContext->Dr2 = (DWORD_PTR)(pConfig->pAddress);
        break;
    case WINHWBP_SLOT_3:
        pContext->Dr3 = (DWORD_PTR)(pConfig->pAddress);
        break;
    default:
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }
    /* Clear existing state */
    pContext->Dr7 &= ~(DR7_LE_GE_NIB_MASK(slot) | DR7_COND_LEN_NIB_MASK(slot));

    /* Only set local enable bit. See WinHwBp_Context_Get */
    if (bEnable)
    {
        pContext->Dr7 |= DR7_LE_MASK(slot);
    }

    pContext->Dr7 |= ((DWORD_PTR)(pConfig->condition) << DR7_COND_POS(slot)) & DR7_COND_MASK(slot);
    pContext->Dr7 |= ((DWORD_PTR)(pConfig->length) << DR7_LEN_POS(slot)) & DR7_LEN_MASK(slot);
    return WINHWBP_STATUS_SUCCESS;
}

WINHWBP_STATUS WinHwBp_SetAuto(_In_ HANDLE hThread, _In_ WINHWBP_PCONFIG pConfig, _Out_ WINHWBP_PSLOT pSlot)
{
    WINHWBP_OP_ARGS args = {0};
    args.setAuto.pConfig = pConfig;
    args.setAuto.pSlot = pSlot;
    return ExecuteOperation(hThread, WINHWBP_OP_SET_AUTO, &args);
}

WINHWBP_STATUS WinHwBp_Context_SetAuto(_Inout_ PCONTEXT pContext, _In_ WINHWBP_PCONFIG pConfig,
                                       _Out_ WINHWBP_PSLOT pSlot)
{
    if (!pContext || !IsValidConfig(pConfig) || !pSlot)
    {
        return WINHWBP_STATUS_INVALID_ARGUMENT;
    }

    /* Iterate through all slots to find an available one, i.e., one that isn't enabled */
    for (WINHWBP_SLOT slot = WINHWBP_SLOT_0; slot <= WINHWBP_SLOT_3; slot++)
    {
        WINHWBP_INFO info;
        if (WinHwBp_Context_Get(pContext, slot, &info) != WINHWBP_STATUS_SUCCESS)
        {
            return WINHWBP_STATUS_INVALID_ARGUMENT;
        }

        if (!info.bIsEnabled)
        {
            WINHWBP_STATUS status = WinHwBp_Context_Set(pContext, slot, pConfig);
            if (status != WINHWBP_STATUS_SUCCESS)
            {
                return status;
            }
            *pSlot = slot;
            return WINHWBP_STATUS_SUCCESS;
        }
    }

    /* All slots are in use */
    return WINHWBP_STATUS_NO_AVAILABLE_SLOTS;
}

WINHWBP_STATUS WinHwBp_Clear(_In_ HANDLE hThread, _In_ WINHWBP_SLOT slot)
{
    WINHWBP_OP_ARGS args = {0};
    args.clear.slot = slot;
    return ExecuteOperation(hThread, WINHWBP_OP_CLEAR, &args);
}

WINHWBP_STATUS WinHwBp_Context_Clear(_Inout_ PCONTEXT pContext, _In_ WINHWBP_SLOT slot)
{
    WINHWBP_CONFIG zeroConfig = {0};
    return WinHwBp_Context_SetEx(pContext, slot, &zeroConfig, FALSE);
}

WINHWBP_STATUS WinHwBp_ClearAll(_In_ HANDLE hThread)
{
    return ExecuteOperation(hThread, WINHWBP_OP_CLEAR_ALL, NULL);
}

WINHWBP_STATUS WinHwBp_Context_ClearAll(_Inout_ PCONTEXT pContext)
{
    for (WINHWBP_SLOT slot = WINHWBP_SLOT_0; slot <= WINHWBP_SLOT_3; slot++)
    {
        WINHWBP_STATUS status = WinHwBp_Context_Clear(pContext, slot);
        if (status != WINHWBP_STATUS_SUCCESS)
        {
            return status;
        }
    }
    return WINHWBP_STATUS_SUCCESS;
}

const char *WinHwBp_StatusToString(_In_ WINHWBP_STATUS status)
{
    switch (status)
    {
    case WINHWBP_STATUS_SUCCESS:
        return "The operation completed successfully.";
    case WINHWBP_STATUS_INVALID_ARGUMENT:
        return "One or more provided arguments are invalid.";
    case WINHWBP_STATUS_SUSPEND_THREAD_FAILED:
        return "Failed to suspend the target thread.";
    case WINHWBP_STATUS_RESUME_THREAD_FAILED:
        return "Failed to resume the target thread.";
    case WINHWBP_STATUS_GET_CONTEXT_FAILED:
        return "Failed to get the thread context.";
    case WINHWBP_STATUS_SET_CONTEXT_FAILED:
        return "Failed to set the thread context.";
    case WINHWBP_STATUS_NO_AVAILABLE_SLOTS:
        return "Could not find an available hardware breakpoint slot.";
    default:
        return "Unknown status code";
    }
}
