#include <string.h>
#include <sys/stat.h>

#include "buffer.h"
#include "buffer.c"
#include "common.c"

#define HASHUTIL_MD5_IMPLEMENTATION
#include "md5.h"
#define REPETITION_TESTER_IMPLEMENTATION
#include "repetition_tester.h"


typedef struct read_parameters read_parameters;
typedef struct test_function test_function;
typedef void test_func_ptr(repetition_tester *tester, read_parameters *params);

static void TestMD5HashFile(repetition_tester *tester, read_parameters *params);

struct read_parameters
{
    const char *FileName;
    buffer Buffer;
};

struct test_function
{
    char const *Name;
    test_func_ptr *Func;
};

test_function TEST_FUNCTIONS[] =
{
    {"TestMD5HashFile", TestMD5HashFile },
};


static void TestMD5HashFile(repetition_tester *tester, read_parameters *params)
{
    while (IsTesting(tester))
    {
        BeginTime(tester);
        MD5_HashFile(params->FileName);
        EndTime(tester);

        CountBytes(tester, params->Buffer.SizeBytes);
    }
}


int main(int argCount, char const *args[])
{
    uint64_t cpuTimerFrequency = EstimateCPUTimerFrequency();
    uint64_t secondsToTry = 10;

    if (argCount != 2)
    {
        fprintf(stderr, "Usage: %s [existing filename]\n", args[0]);
        return 0;
    }

    const char *fileName = args[1];
#if _WIN32
    struct __stat64 stat;
    _stat64(fileName, &stat);
#else
    struct stat stats;
    stat(fileName, &stats);
#endif

    read_parameters params = {0};
    params.FileName = fileName;
    params.Buffer = BufferAllocate(stats.st_size);
    if (params.Buffer.SizeBytes == 0)
    {
        fprintf(stderr, "[ERROR] Test data size must be non-zero\n");
        return 1;
    }

    repetition_tester testers[ArrayCount(TEST_FUNCTIONS)] = {0};

    for(;;)
    {
        for(uint32_t funcIndex = 0; funcIndex < ArrayCount(TEST_FUNCTIONS); ++funcIndex)
        {
            repetition_tester *tester = &testers[funcIndex];
            test_function testFunc = TEST_FUNCTIONS[funcIndex];

            printf("\n--- %s ---\n", testFunc.Name);
            NewTestWave(tester, params.Buffer.SizeBytes, cpuTimerFrequency, secondsToTry);
            testFunc.Func(tester, &params);
        }
    }

    return 0;
}
