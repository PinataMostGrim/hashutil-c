#include <string.h>
#include <sys/stat.h>

#include "buffer.h"
#include "supported_hashes.h"

#include "buffer.c"
#include "common.c"
#include "supported_hashes.c"

#define HASHUTIL_MD5_IMPLEMENTATION
#include "md5.h"
#define HASHUTIL_SHA1_IMPLEMENTATION
#include "sha1.h"
#define HASHUTIL_SHA2_IMPLEMENTATION
#include "sha2.h"

#define REPETITION_TESTER_IMPLEMENTATION
#include "repetition_tester.h"


typedef struct read_parameters read_parameters;

struct read_parameters
{
    const char *FileName;
    buffer Buffer;
    hash_algorithm HashAlgorithm;
};

hash_algorithm TEST_HASHES[] = {
    hash_md5,
    hash_sha1,
    hash_sha224,
    hash_sha256,
    hash_sha384,
    hash_sha512,
    hash_sha512_224,
    hash_sha512_256,
};


static void TestHashFile(repetition_tester *tester, read_parameters *params)
{
    while (IsTesting(tester))
    {
        BeginTime(tester);
        switch (params->HashAlgorithm)
        {
            case hash_md5:
                MD5_HashFile(params->FileName);
                break;
            case hash_sha1:
                SHA1_HashFile(params->FileName);
                break;
            case hash_sha224:
                SHA2_HashFileSHA224(params->FileName);
                break;
            case hash_sha256:
                SHA2_HashFileSHA256(params->FileName);
                break;
            case hash_sha384:
                SHA2_HashFileSHA384(params->FileName);
                break;
            case hash_sha512:
                SHA2_HashFileSHA512(params->FileName);
                break;
            case hash_sha512_224:
                SHA2_HashFileSHA512_224(params->FileName);
                break;
            case hash_sha512_256:
                SHA2_HashFileSHA512_256(params->FileName);
                break;
            default:
                Error(tester, "Unhandled hash_algorithm!");
                break;
        }
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

    repetition_tester testers[ArrayCount(TEST_HASHES)] = {0};

    for(;;)
    {
        for(uint32_t funcIndex = 0; funcIndex < ArrayCount(TEST_HASHES); ++funcIndex)
        {
            repetition_tester *tester = &testers[funcIndex];
            params.HashAlgorithm = TEST_HASHES[funcIndex];

            printf("\n--- %s ---\n", GetHashMenemonic(params.HashAlgorithm));
            NewTestWave(tester, params.Buffer.SizeBytes, cpuTimerFrequency, secondsToTry);
            TestHashFile(tester, &params);
        }
    }

    return 0;
}
