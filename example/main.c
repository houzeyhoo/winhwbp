#include <winhwbp.h>

#include <stdio.h>

HANDLE worker_continue_event_g = NULL;
HANDLE worker_done_event_g = NULL;

static volatile int my_variable_g = 0;

static volatile int other_variable_g = 0;

static __declspec(noinline) void my_function(void)
{
    fflush(stdout);
}

LONG WINAPI ve_handler(EXCEPTION_POINTERS *e)
{
    /* Hardware breakpoints always trigger single step exceptions */
    if (e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /*
     * There are many ways to structure your handler and WinHwBp makes no assumptions about how you do it. Here, we
     * simply iterate through all slots to see which one was triggered.
     */
    for (WINHWBP_SLOT slot = WINHWBP_SLOT_0; slot <= WINHWBP_SLOT_3; slot++)
    {
        WINHWBP_INFO info;
        WINHWBP_STATUS status = WinHwBp_Context_Get(e->ContextRecord, slot, &info);
        if (status != WINHWBP_STATUS_SUCCESS)
        {
            printf("[VEH] WinHwBp_Context_Get failed for slot %d: %s\n", slot, WinHwBp_StatusToString(status));
            continue;
        }

        /*
         * When determining which breakpoint was triggered, it's good to check bIsEnabled and bIsConditionMet
         * together, as the condition flag may be set to true even if the breakpoint is disabled. It's possible for
         * one exception to trigger multiple breakpoints.
         */
        if (info.bIsEnabled && info.bIsConditionMet)
        {
            printf("[VEH] Breakpoint exception received for slot %d\n", slot);
            printf(" -> Address: %p\n", info.config.pAddress);
            printf(" -> Condition: %d\n", info.config.condition);
            printf(" -> Length: %d\n", info.config.length);

            /*
             * Also, if the breakpoint condition is COND_EXECUTE, you likely want to either clear the breakpoint here
             * or set the resume flag before exiting the handler, or it'll keep triggering on the same instruction.
             */
            if (info.config.condition == WINHWBP_COND_EXECUTE)
            {
                e->ContextRecord->EFlags |= 0x10000;
            }
            break;
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI worker(void *param)
{
    (void)param;

    printf("[WORKER] Calling my_function...\n");
    my_function();

    printf("[WORKER] Writing to my_variable_g...\n");
    my_variable_g = 42;

    printf("[WORKER] Reading from other_variable_g...\n");
    volatile int tmp = other_variable_g;

    /* Wait until main thread lets us exit */
    SetEvent(worker_done_event_g);
    WaitForSingleObject(worker_continue_event_g, INFINITE);
    return 0;
}

int main()
{
    worker_continue_event_g = CreateEvent(NULL, FALSE, FALSE, NULL);
    worker_done_event_g = CreateEvent(NULL, FALSE, FALSE, NULL);

    /* We'll create the thread as suspended for demonstration purposes */
    HANDLE thread = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, NULL);
    AddVectoredExceptionHandler(1, ve_handler);

    /*
     * Every operation in WinHwBp can be performed either on a thread, or directly on its context. The former is great
     * for simpler use-cases where you'd want less boilerplate, while the latter offers more control and is suitable
     * for more complex scenarios, e.g., batching multiple operations into transactions without incurring the overhead
     * of multiple suspend/resume cycles.
     *
     * We'll go over both methods in this example, starting with the context-based approach, as the target thread is
     * currently in a suspended state.
     */
    CONTEXT ctx = {.ContextFlags = CONTEXT_DEBUG_REGISTERS};
    if (!GetThreadContext(thread, &ctx))
    {
        printf("[MAIN] GetThreadContext failed: %lu\n", GetLastError());
        return 1;
    }

    /*
     * We'll set the first breakpoint on slot 0 and configure it to trigger on execution of my_function. Keep in mind
     * that when using COND_EXECUTE, you need to ensure that the length is set to LEN_1.
     */
    WINHWBP_CONFIG config = {.pAddress = &my_function, .condition = WINHWBP_COND_EXECUTE, .length = WINHWBP_LEN_1};
    WINHWBP_STATUS status = WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_0, &config);
    if (status)
    {
        printf("[MAIN] WinHwBp_Context_Set failed for slot 0: %s\n", WinHwBp_StatusToString(status));
        return 1;
    }
    printf("[MAIN] Breakpoint on my_function set on slot 0\n");

    /* Next, we'll configure a breakpoint to trigger when my_variable_g is written to. */
    config.pAddress = (PVOID)&my_variable_g;
    config.condition = WINHWBP_COND_WRITE;
    config.length = WINHWBP_LEN_4;
    /*
     * This time, we'll use SetAuto, which will pick a suitable slot for us. If an available slot is found, it will be
     * returned via the usedSlot parameter
     */
    WINHWBP_SLOT usedSlot;
    status = WinHwBp_Context_SetAuto(&ctx, &config, &usedSlot);
    if (status)
    {
        printf("[MAIN] WinHwBp_Context_SetAuto failed for slot %d: %s\n", usedSlot, WinHwBp_StatusToString(status));
        return 1;
    }
    printf("[MAIN] Breakpoint on my_variable_g set on slot %d\n", usedSlot);

    /* We'll configure the final breakpoint to trigger on when other_variable_g is read or written to. */
    config.pAddress = (PVOID)&other_variable_g;
    config.condition = WINHWBP_COND_READ_WRITE;
    config.length = WINHWBP_LEN_4;
    status = WinHwBp_Context_SetAuto(&ctx, &config, &usedSlot);
    if (status)
    {
        printf("[MAIN] WinHwBp_Context_SetAuto failed for slot %d: %s\n", usedSlot, WinHwBp_StatusToString(status));
        return 1;
    }
    printf("[MAIN] Breakpoint on other_variable_g set on slot %d\n", usedSlot);

    /* Now that we've done everything we wanted, let's write the context and resume the thread */
    printf("[MAIN] Writing context and resuming worker thread...\n");
    if (!SetThreadContext(thread, &ctx))
    {
        printf("[MAIN] SetThreadContext failed: %lu\n", GetLastError());
        return 1;
    }
    if (ResumeThread(thread) == (DWORD)-1)
    {
        printf("[MAIN] ResumeThread failed: %lu\n", GetLastError());
        return 1;
    }
    WaitForSingleObject(worker_done_event_g, INFINITE);

    /* Since the thread is running, we'll now use the handle-based API to inspect its breakpoint state */
    printf("[MAIN] Dumping breakpoint state of worker thread...\n");
    for (WINHWBP_SLOT slot = WINHWBP_SLOT_0; slot <= WINHWBP_SLOT_3; slot++)
    {
        WINHWBP_INFO info;
        status = WinHwBp_Get(thread, slot, &info);
        if (status)
        {
            printf("[MAIN] WinHwBp_Get failed for slot %d: %s\n", slot, WinHwBp_StatusToString(status));
            return 1;
        }

        const char *cond_str = info.config.condition == WINHWBP_COND_EXECUTE      ? "EXECUTE"
                               : info.config.condition == WINHWBP_COND_WRITE      ? "WRITE"
                               : info.config.condition == WINHWBP_COND_READ_WRITE ? "READ/WRITE"
                                                                                  : "UNKNOWN";
        int len_bytes = info.config.length == WINHWBP_LEN_1   ? 1
                        : info.config.length == WINHWBP_LEN_2 ? 2
                        : info.config.length == WINHWBP_LEN_4 ? 4
                        : info.config.length == WINHWBP_LEN_8 ? 8
                                                              : -1;

        printf(" -> Slot: %d, Address: 0x%p, Condition: %-10s, Length: %d, IsEnabled: %-5s, IsConditionMet: %s\n",
               info.slot, info.config.pAddress, cond_str, len_bytes, info.bIsEnabled ? "TRUE" : "FALSE",
               info.bIsConditionMet ? "TRUE" : "FALSE");
    }

    /* We can reset the state entirely by clearing all breakpoints */
    if (WinHwBp_ClearAll(thread) != WINHWBP_STATUS_SUCCESS)
    {
        printf("[MAIN] WinHwBp_ClearAll failed\n");
        return 1;
    }

    SetEvent(worker_continue_event_g);
    return 0;
}
