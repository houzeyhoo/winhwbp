#include <winhwbp.h>
#include <drx.h>

#include <stdio.h>

static struct
{
    int total_count;
    int failed_count;
} test_state_g = {0};

#define MESSAGE_SIZE 256

#define TEST_MARKER()                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        test_state_g.total_count++;                                                                                    \
    } while (0)

#define TEST_FAIL(msg)                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        test_state_g.failed_count++;                                                                                   \
        printf("FAIL (%s:%d): %s\n", __FILE__, __LINE__, msg);                                                         \
    } while (0)

#define ASSERT_TRUE(cond)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        TEST_MARKER();                                                                                                 \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            TEST_FAIL("ASSERT_TRUE " #cond " != TRUE");                                                                \
        }                                                                                                              \
    } while (0)

#define ASSERT_FALSE(cond)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        TEST_MARKER();                                                                                                 \
        if (cond)                                                                                                      \
        {                                                                                                              \
            TEST_FAIL("ASSERT_FALSE " #cond " != FALSE");                                                              \
        }                                                                                                              \
    } while (0)

#define ASSERT_EQUAL_INT(value, expected)                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        TEST_MARKER();                                                                                                 \
        int _value_ = (value);                                                                                         \
        int _expected_ = (expected);                                                                                   \
        if (_value_ != _expected_)                                                                                     \
        {                                                                                                              \
            char _msg_[MESSAGE_SIZE];                                                                                  \
            snprintf(_msg_, sizeof(_msg_), "ASSERT_EQUAL_INT " #value " (%d) != " #expected " (%d)", _value_,          \
                     _expected_);                                                                                      \
            TEST_FAIL(_msg_);                                                                                          \
        }                                                                                                              \
    } while (0)

#define ASSERT_EQUAL_INT64(value, expected)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        TEST_MARKER();                                                                                                 \
        long long int _value_ = (long long int)(value);                                                                \
        long long int _expected_ = (long long int)(expected);                                                          \
        if (_value_ != _expected_)                                                                                     \
        {                                                                                                              \
            char _msg_[MESSAGE_SIZE];                                                                                  \
            snprintf(_msg_, sizeof(_msg_), "ASSERT_EQUAL_INT64 " #value " (%lld) != " #expected " (%lld)", _value_,    \
                     _expected_);                                                                                      \
            TEST_FAIL(_msg_);                                                                                          \
        }                                                                                                              \
    } while (0)

#define ASSERT_EQUAL_PTR(value, expected)                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        TEST_MARKER();                                                                                                 \
        const void *_value_ = (const void *)(value);                                                                   \
        const void *_expected_ = (const void *)(expected);                                                             \
        if (_value_ != _expected_)                                                                                     \
        {                                                                                                              \
            char _msg_[MESSAGE_SIZE];                                                                                  \
            snprintf(_msg_, sizeof(_msg_), "ASSERT_EQUAL_PTR " #value " (%p) != " #expected " (%p)", _value_,          \
                     _expected_);                                                                                      \
            TEST_FAIL(_msg_);                                                                                          \
        }                                                                                                              \
    } while (0)

#define ASSERT_SUCCESS(status)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        TEST_MARKER();                                                                                                 \
        WINHWBP_STATUS _status_ = (status);                                                                            \
        if (_status_ != WINHWBP_STATUS_SUCCESS)                                                                        \
        {                                                                                                              \
            char _msg_[MESSAGE_SIZE];                                                                                  \
            snprintf(_msg_, sizeof(_msg_), "ASSERT_SUCCESS " #status " (%d) != WINHWBP_STATUS_SUCCESS", _status_);     \
            TEST_FAIL(_msg_);                                                                                          \
        }                                                                                                              \
    } while (0)

static CONTEXT make_empty_context(void)
{
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return context;
}

static void fill_context(CONTEXT *ctx, int slot, void *address, int le, int ge, int cond, int len)
{
    switch (slot)
    {
    case WINHWBP_SLOT_0:
        ctx->Dr0 = (DWORD_PTR)address;
        break;
    case WINHWBP_SLOT_1:
        ctx->Dr1 = (DWORD_PTR)address;
        break;
    case WINHWBP_SLOT_2:
        ctx->Dr2 = (DWORD_PTR)address;
        break;
    case WINHWBP_SLOT_3:
        ctx->Dr3 = (DWORD_PTR)address;
        break;
    }
    ctx->Dr7 &= ~(DR7_LE_GE_NIB_MASK(slot) | DR7_COND_LEN_NIB_MASK(slot));
    if (le)
    {
        ctx->Dr7 |= DR7_LE_MASK(slot);
    }
    if (ge)
    {
        ctx->Dr7 |= DR7_GE_MASK(slot);
    }
    ctx->Dr7 |= ((DWORD_PTR)(cond) << DR7_COND_POS(slot)) & DR7_COND_MASK(slot);
    ctx->Dr7 |= ((DWORD_PTR)(len) << DR7_LEN_POS(slot)) & DR7_LEN_MASK(slot);
}

static WINHWBP_CONFIG make_config(void *address, int cond, int len)
{
    WINHWBP_CONFIG config = {0};
    config.pAddress = address;
    config.condition = cond;
    config.length = len;
    return config;
}

static void test_get(void)
{
    CONTEXT ctx = make_empty_context();
    WINHWBP_INFO info;

    /* Read empty register */
    ASSERT_SUCCESS(WinHwBp_Context_Get(&ctx, WINHWBP_SLOT_0, &info));
    ASSERT_EQUAL_PTR(info.config.pAddress, NULL);
    ASSERT_EQUAL_INT(info.config.condition, 0);
    ASSERT_EQUAL_INT(info.config.length, 0);
    ASSERT_EQUAL_INT(info.slot, 0);
    ASSERT_FALSE(info.bIsEnabled);
    ASSERT_FALSE(info.bIsConditionMet);

    /* Standard get */
    fill_context(&ctx, WINHWBP_SLOT_1, (void *)0x1234, 1, 0, WINHWBP_COND_READ_WRITE, WINHWBP_LEN_4);
    ASSERT_SUCCESS(WinHwBp_Context_Get(&ctx, WINHWBP_SLOT_1, &info));
    ASSERT_EQUAL_PTR(info.config.pAddress, (void *)0x1234);
    ASSERT_EQUAL_INT(info.config.condition, WINHWBP_COND_READ_WRITE);
    ASSERT_EQUAL_INT(info.config.length, WINHWBP_LEN_4);
    ASSERT_EQUAL_INT(info.slot, WINHWBP_SLOT_1);
    ASSERT_TRUE(info.bIsEnabled);

    /* Standard get, but for breakpoint enabled via GE */
    fill_context(&ctx, WINHWBP_SLOT_2, (void *)0x5678, 0, 1, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    ASSERT_SUCCESS(WinHwBp_Context_Get(&ctx, WINHWBP_SLOT_2, &info));
    ASSERT_EQUAL_PTR(info.config.pAddress, (void *)0x5678);
    ASSERT_EQUAL_INT(info.config.condition, WINHWBP_COND_WRITE);
    ASSERT_EQUAL_INT(info.config.length, WINHWBP_LEN_2);
    ASSERT_EQUAL_INT(info.slot, WINHWBP_SLOT_2);
    ASSERT_TRUE(info.bIsEnabled);

    /* Invalid arguments */
    ASSERT_EQUAL_INT(WinHwBp_Get(NULL, WINHWBP_SLOT_0, &info), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Get(INVALID_HANDLE_VALUE, WINHWBP_SLOT_0, &info), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Get(NULL, WINHWBP_SLOT_0, &info), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Get(&ctx, WINHWBP_SLOT_0, NULL), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Get(&ctx, 6, &info), WINHWBP_STATUS_INVALID_ARGUMENT);
}

static void test_set(void)
{
    CONTEXT ctx = make_empty_context();
    WINHWBP_CONFIG config = {0};

    /* Standard set */
    config = make_config((void *)0x1234, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    ASSERT_SUCCESS(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_0, &config));
    ASSERT_EQUAL_PTR((void *)ctx.Dr0, (void *)0x1234);
    ASSERT_TRUE(ctx.Dr7 & DR7_LE_MASK(WINHWBP_SLOT_0));
    ASSERT_FALSE(ctx.Dr7 & DR7_GE_MASK(WINHWBP_SLOT_0));
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_COND_MASK(WINHWBP_SLOT_0)) >> DR7_COND_POS(WINHWBP_SLOT_0), WINHWBP_COND_WRITE);
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_LEN_MASK(WINHWBP_SLOT_0)) >> DR7_LEN_POS(WINHWBP_SLOT_0), WINHWBP_LEN_2);

    /* Overwrite same slot */
    config = make_config((void *)0x5678, WINHWBP_COND_EXECUTE, WINHWBP_LEN_1);
    ASSERT_SUCCESS(WinHwBp_Context_SetEx(&ctx, WINHWBP_SLOT_0, &config, FALSE));
    ASSERT_EQUAL_PTR((void *)ctx.Dr0, (void *)0x5678);
    ASSERT_FALSE(ctx.Dr7 & DR7_LE_MASK(WINHWBP_SLOT_0));
    ASSERT_FALSE(ctx.Dr7 & DR7_GE_MASK(WINHWBP_SLOT_0));
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_COND_MASK(WINHWBP_SLOT_0)) >> DR7_COND_POS(WINHWBP_SLOT_0), WINHWBP_COND_EXECUTE);
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_LEN_MASK(WINHWBP_SLOT_0)) >> DR7_LEN_POS(WINHWBP_SLOT_0), WINHWBP_LEN_1);

    /* Extended set (disabled breakpoint) */
    config = make_config((void *)0x9ABC, WINHWBP_COND_READ_WRITE, WINHWBP_LEN_4);
    ASSERT_SUCCESS(WinHwBp_Context_SetEx(&ctx, WINHWBP_SLOT_1, &config, FALSE));
    ASSERT_EQUAL_PTR((void *)ctx.Dr1, (void *)0x9ABC);
    ASSERT_FALSE(ctx.Dr7 & DR7_LE_MASK(WINHWBP_SLOT_1));
    ASSERT_FALSE(ctx.Dr7 & DR7_GE_MASK(WINHWBP_SLOT_1));
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_COND_MASK(WINHWBP_SLOT_1)) >> DR7_COND_POS(WINHWBP_SLOT_1),
                     WINHWBP_COND_READ_WRITE);
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_LEN_MASK(WINHWBP_SLOT_1)) >> DR7_LEN_POS(WINHWBP_SLOT_1), WINHWBP_LEN_4);

    const CONTEXT ctxSnapshot = ctx;

    /* Invalid arguments */
    ASSERT_EQUAL_INT(WinHwBp_Set(NULL, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Set(INVALID_HANDLE_VALUE, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(NULL, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, NULL), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, 6, &config), WINHWBP_STATUS_INVALID_ARGUMENT);

    /* Invalid config - illegal condition */
    config = make_config((void *)0x1234, 2, WINHWBP_LEN_2);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
    config = make_config((void *)0x1234, 5, WINHWBP_LEN_2);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);

    /* Invalid config - illegal length */
#if !defined(_WIN64)
    config = make_config((void *)0x1234, WINHWBP_COND_WRITE, 2);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
#endif
    config = make_config((void *)0x1234, WINHWBP_COND_WRITE, 5);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);

    /* Invalid config - cond=execute and len!=1 */
    config = make_config((void *)0x1234, WINHWBP_COND_EXECUTE, WINHWBP_LEN_2);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);

    /* Invalid config - illegal address alignment */
    config = make_config((void *)0x1235, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
    config = make_config((void *)0x1236, WINHWBP_COND_WRITE, WINHWBP_LEN_4);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
#if defined(_WIN64)
    config = make_config((void *)0x1235, WINHWBP_COND_WRITE, WINHWBP_LEN_8);
    ASSERT_EQUAL_INT(WinHwBp_Context_Set(&ctx, WINHWBP_SLOT_3, &config), WINHWBP_STATUS_INVALID_ARGUMENT);
#endif

    /* Make sure none of the invalid calls mutated the context */
    ASSERT_EQUAL_INT(memcmp(&ctx, &ctxSnapshot, sizeof(CONTEXT)), 0);
}

static void test_set_auto(void)
{
    CONTEXT ctx = make_empty_context();
    WINHWBP_CONFIG config = {0};

    /* Standard auto set */
    fill_context(&ctx, WINHWBP_SLOT_0, (void *)0x1234, 1, 0, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    config = make_config((void *)0x5678, WINHWBP_COND_READ_WRITE, WINHWBP_LEN_4);
    WINHWBP_SLOT slot;
    ASSERT_SUCCESS(WinHwBp_Context_SetAuto(&ctx, &config, &slot));
    ASSERT_EQUAL_INT(slot, WINHWBP_SLOT_1);

    /* Check behavior when all slots are occupied */
    fill_context(&ctx, WINHWBP_SLOT_0, (void *)0x1000, 1, 0, WINHWBP_COND_EXECUTE, WINHWBP_LEN_1);
    fill_context(&ctx, WINHWBP_SLOT_1, (void *)0x1001, 1, 0, WINHWBP_COND_EXECUTE, WINHWBP_LEN_1);
    fill_context(&ctx, WINHWBP_SLOT_2, (void *)0x1002, 1, 0, WINHWBP_COND_EXECUTE, WINHWBP_LEN_1);
    fill_context(&ctx, WINHWBP_SLOT_3, (void *)0x1003, 1, 0, WINHWBP_COND_EXECUTE, WINHWBP_LEN_1);
    config = make_config((void *)0x1004, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    ASSERT_EQUAL_INT(WinHwBp_Context_SetAuto(&ctx, &config, &slot), WINHWBP_STATUS_NO_AVAILABLE_SLOTS);

    /* Invalid arguments */
    ASSERT_EQUAL_INT(WinHwBp_SetAuto(NULL, &config, &slot), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_SetAuto(INVALID_HANDLE_VALUE, NULL, &slot), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_SetAuto(NULL, &config, &slot), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_SetAuto(&ctx, NULL, &slot), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_SetAuto(&ctx, &config, NULL), WINHWBP_STATUS_INVALID_ARGUMENT);
}

static void test_clear(void)
{
    CONTEXT ctx = make_empty_context();

    /* Standard clear */
    fill_context(&ctx, WINHWBP_SLOT_0, (void *)0x1234, 1, 0, WINHWBP_COND_READ_WRITE, WINHWBP_LEN_4);
    fill_context(&ctx, WINHWBP_SLOT_2, (void *)0x5678, 0, 1, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    ASSERT_SUCCESS(WinHwBp_Context_Clear(&ctx, WINHWBP_SLOT_0));
    ASSERT_EQUAL_PTR((void *)ctx.Dr0, NULL);
    ASSERT_FALSE(ctx.Dr7 & DR7_LE_MASK(WINHWBP_SLOT_0));
    ASSERT_FALSE(ctx.Dr7 & DR7_GE_MASK(WINHWBP_SLOT_0));
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_COND_MASK(WINHWBP_SLOT_0)) >> DR7_COND_POS(WINHWBP_SLOT_0), 0);
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_LEN_MASK(WINHWBP_SLOT_0)) >> DR7_LEN_POS(WINHWBP_SLOT_0), 0);

    /* Make sure other slot was not affected */
    ASSERT_EQUAL_PTR((void *)ctx.Dr2, (void *)0x5678);
    ASSERT_TRUE(ctx.Dr7 & DR7_GE_MASK(WINHWBP_SLOT_2));
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_COND_MASK(WINHWBP_SLOT_2)) >> DR7_COND_POS(WINHWBP_SLOT_2), WINHWBP_COND_WRITE);
    ASSERT_EQUAL_INT((ctx.Dr7 & DR7_LEN_MASK(WINHWBP_SLOT_2)) >> DR7_LEN_POS(WINHWBP_SLOT_2), WINHWBP_LEN_2);

    /* Invalid arguments */
    ASSERT_EQUAL_INT(WinHwBp_Clear(NULL, WINHWBP_SLOT_0), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Clear(INVALID_HANDLE_VALUE, WINHWBP_SLOT_0), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Clear(NULL, WINHWBP_SLOT_0), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_Clear(NULL, 6), WINHWBP_STATUS_INVALID_ARGUMENT);
}

static void test_clear_all(void)
{
    CONTEXT ctx = make_empty_context();
    const CONTEXT ctxSnapshot = ctx;

    /* Standard clear all */
    fill_context(&ctx, WINHWBP_SLOT_0, (void *)0x1234, 1, 0, WINHWBP_COND_READ_WRITE, WINHWBP_LEN_4);
    fill_context(&ctx, WINHWBP_SLOT_1, (void *)0x5678, 0, 1, WINHWBP_COND_WRITE, WINHWBP_LEN_2);
    fill_context(&ctx, WINHWBP_SLOT_2, (void *)0x9ABC, 1, 1, WINHWBP_COND_EXECUTE, WINHWBP_LEN_1);
    ASSERT_SUCCESS(WinHwBp_Context_ClearAll(&ctx));
    ASSERT_EQUAL_INT(memcmp(&ctx, &ctxSnapshot, sizeof(CONTEXT)), 0);

    /* Invalid arguments */
    ASSERT_EQUAL_INT(WinHwBp_ClearAll(NULL), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_ClearAll(INVALID_HANDLE_VALUE), WINHWBP_STATUS_INVALID_ARGUMENT);
    ASSERT_EQUAL_INT(WinHwBp_Context_ClearAll(NULL), WINHWBP_STATUS_INVALID_ARGUMENT);
}

static void test_end_to_end(void)
{
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, (LPVOID)100000, CREATE_SUSPENDED, NULL);

    /* Set and get back */
    WINHWBP_CONFIG config = make_config((void *)0x1234, WINHWBP_COND_WRITE, WINHWBP_LEN_4);
    WINHWBP_SLOT slot;
    ASSERT_SUCCESS(WinHwBp_SetAuto(thread, &config, &slot));
    WINHWBP_INFO info;
    ASSERT_SUCCESS(WinHwBp_Get(thread, slot, &info));
    ASSERT_EQUAL_PTR(info.config.pAddress, (void *)0x1234);
    ASSERT_EQUAL_INT(info.config.condition, WINHWBP_COND_WRITE);
    ASSERT_EQUAL_INT(info.config.length, WINHWBP_LEN_4);
    ASSERT_EQUAL_INT(info.slot, slot);
    ASSERT_TRUE(info.bIsEnabled);

    TerminateThread(thread, 0);
    CloseHandle(thread);
}

typedef void (*TestProc)(void);

typedef struct
{
    const char *name;
    TestProc proc;
} TestTableEntry;

static const TestTableEntry test_table[] = {
    {"get", test_get},
    {"set", test_set},
    {"set_auto", test_set_auto},
    {"clear", test_clear},
    {"clear_all", test_clear_all},
    {"end_to_end", test_end_to_end},
};

static int run_test(const char *name)
{
    for (size_t i = 0; i < sizeof(test_table) / sizeof(test_table[0]); i++)
    {
        if (strcmp(name, test_table[i].name) == 0)
        {
            TestTableEntry test = test_table[i];
            printf("RUN  %s\n", test.name);
            test.proc();
            if (test_state_g.failed_count > 0)
            {
                printf("FAIL %s\n", test.name);
                return test_state_g.failed_count;
            }
            printf("OK   %s\n", test.name);
            return 0;
        }
    }
    /* Test not found */
    return -1;
}

static void print_test_names(void)
{
    for (size_t i = 0; i < sizeof(test_table) / sizeof(test_table[0]); i++)
    {
        printf("%s\n", test_table[i].name);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_test_names();
        return 0;
    }
    /* Return -1 when test not found, 0 when all's ok, >0 on fail */
    return run_test(argv[1]);
}
