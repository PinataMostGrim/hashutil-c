/* TODO (Aaron):
    - Add readme / documentation to file
*/

/*  test-hashutil.c

    Test driver for md5.h, sha2.h and sha2.h. Ensures modules produce correct hashes
    for files and strings.
*/

#define HASHUTIL_MD5_IMPLEMENTATION
#include "md5.h"
#define HASHUTIL_SHA1_IMPLEMENTATION
#include "sha1.h"
#define HASHUTIL_SHA2_IMPLEMENTATION
#include "sha2.h"
#include "common.c"

#include <stdint.h>
#include <string.h>

static int32_t PASSING_TESTS = 0;
static int32_t FAILING_TESTS = 0;
static bool ALL_TESTS_PASSED = true;


static char *Messages[] =
{
    "",
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "The quick brown fox jumps over the lazy dog over and ove",
    "The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again",
};

static char *Filenames[] =
{
    "etc/test.txt",
    "etc/test2.txt",
};


static void EvaluateResult(char *messagePtr, char *targetDigest, char *digestStr)
{
    if (strcmp(digestStr, targetDigest) == 0)
    {
        printf("SUCCEEDED: '%s' [%s]\n", messagePtr, digestStr);
        PASSING_TESTS++;

        return;
    }

    printf("FAILED: '%s'\n", messagePtr);
    printf("\tExpected:\t%s\n", targetDigest);
    printf("\tReceived:\t%s\n", digestStr);

    ALL_TESTS_PASSED = false;
    FAILING_TESTS++;
}


void PerformMD5Tests()
{
     printf("MD5 hash tests:\n");

    md5_context md5Context;

    char *md5MessageTargetDigests[] =
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "900150983cd24fb0d6963f7d28e17f72",
        "8215ef0796a20bcaaae116d3876c664a",
        "01ccfd3d9076cfc34e7e81626373a5d2",
        "e6cc782eea06cd67bf26125785ea805e",
    };

    char *md5FileTargetDigests[] =
    {
        "05831eb88a34bfe953de0afc2b43f46d",
        "d41d8cd98f00b204e9800998ecf8427e",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(md5MessageTargetDigests),
                  "Mismatched number of messages and target digests for MD5");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(md5FileTargetDigests),
                  "Mismatched number of files and target digests for MD5");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        md5Context = MD5_HashString(Messages[i]);
        EvaluateResult(Messages[i], md5MessageTargetDigests[i], md5Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        md5Context = MD5_HashFile(Filenames[i]);
        EvaluateResult(Filenames[i], md5FileTargetDigests[i], md5Context.DigestStr);
    }

    printf("\n");
}


void PerformSHA1Tests()
{
    printf("SHA1 hash tests:\n");

    sha1_context sha1Context;

    char *sha1MessageTargetDigests[] =
    {
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        "51c6df96407f4c6b257f5767247ac6b3ad71d773",
        "b1d31797695eb0c2e369dd4149a80cbb58ba48e0",
    };

    char *sha1FileTargetDigests[] =
    {
        "3c5a24b30b738ec655e7c1aff04743285f07d690",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha1MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA1");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha1FileTargetDigests),
                  "Mismatched number of files and target digests for SHA1");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha1Context = SHA1_HashString(Messages[i]);
        EvaluateResult(Messages[i], sha1MessageTargetDigests[i], sha1Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha1Context = SHA1_HashFile(Filenames[i]);
        EvaluateResult(Filenames[i], sha1FileTargetDigests[i], sha1Context.DigestStr);
    }

    printf("\n");
}


void PerformSHA256Tests()
{
    printf("SHA224 hash tests:\n");

    sha2_256_context sha256Context;

    char *sha224MessageTargetDigests[] =
    {
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        "b5b48277b755e58a7ef4b3f759020696beeb77684ae4e6f8d6f113ed",
        "9e04184fee6c5497488121d85dd19df057a05aae5e1bac5a17789fe8",
    };

    char *sha224FileTargetDigests[] =
    {
        "c02d67484dba7f2752cbc770a764968ef8165ebc0a6bdc38c072ca68",
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha224MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA224");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha224FileTargetDigests),
                  "Mismatched number of files and target digests for SHA224");

    // Hash strings
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha256Context = SHA2_HashStringSHA224(Messages[i]);
        EvaluateResult(Messages[i], sha224MessageTargetDigests[i], sha256Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha256Context = SHA2_HashFileSHA224(Filenames[i]);
        EvaluateResult(Filenames[i], sha224FileTargetDigests[i], sha256Context.DigestStr);
    }

    printf("\n");


    printf("SHA256 hash tests:\n");

    char *sha256MessageTargetDigests[] =
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "42715e6bf04cb5121185b6eff264576c590b0716b939ec61dc62490662bd7718",
        "5e471d49eef9c7f859044d9ef2d31175d94384953f842ba02e20e06b77946408",
    };

    char *sha256FileTargetDigests[] =
    {
        "1821202d3724f9648427c0bc74433e0f21d7e7293ab5da8c734bacb673f0c304",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha256MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA256");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha256FileTargetDigests),
                  "Mismatched number of files and target digests for SHA256");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha256Context = SHA2_HashStringSHA256(Messages[i]);
        EvaluateResult(Messages[i], sha256MessageTargetDigests[i], sha256Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha256Context = SHA2_HashFileSHA256(Filenames[i]);
        EvaluateResult(Filenames[i], sha256FileTargetDigests[i], sha256Context.DigestStr);
    }

    printf("\n");
}


void PerformSHA512Tests()
{
    sha2_512_context sha512Context;

    printf("SHA512/224 hash tests:\n");

    char *sha512_224MessageTargetDigests[] =
    {
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
        "e7863d028bbcea0fc84c0c7f53ac4dc5bf4f055964cfdac0dbe6e6e6",
        "b599fad02f1546bef9765e09741262e850f3971373a22ddc5b81d9aa",
    };

    char *sha512_224FileTargetDigests[] =
    {
        "02bbf4fd21277bd9d520ded218d76eb4406f373909110e6626fcd0d5",
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha512_224MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA512/224");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha512_224FileTargetDigests),
                  "Mismatched number of files and target digests for SHA512/224");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha512Context = SHA2_HashStringSHA512_224(Messages[i]);
        EvaluateResult(Messages[i], sha512_224MessageTargetDigests[i], sha512Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha512Context = SHA2_HashFileSHA512_224(Filenames[i]);
        EvaluateResult(Filenames[i], sha512_224FileTargetDigests[i], sha512Context.DigestStr);
    }

    printf("\n");

    printf("SHA512/256 hash tests:\n");

    char *sha512_256MessageTargetDigests[] =
    {
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
        "a19a9ac89dd2da9ce45ef52b33ae26e181986b559f3985502d0ded15e7050f5f",
        "34ce5007b7fb6734cd95a422ac4e1220122077c7165e048dad16a5cbca610676",
    };

    char *sha512_256FileTargetDigests[] =
    {
        "06f294ed155b4f3625cb9ffed2b6ef3f128b270e223f01df8408df5a7c03982b",
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha512_256MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA512/256");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha512_256FileTargetDigests),
                  "Mismatched number of files and target digests for SHA512/256");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha512Context = SHA2_HashStringSHA512_256(Messages[i]);
        EvaluateResult(Messages[i], sha512_256MessageTargetDigests[i], sha512Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha512Context = SHA2_HashFileSHA512_256(Filenames[i]);
        EvaluateResult(Filenames[i], sha512_256FileTargetDigests[i], sha512Context.DigestStr);
    }

    printf("\n");

    printf("SHA384 hash tests:\n");

    char *sha384MessageTargetDigests[] =
    {
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
        "f05d0f630e9e2c38d9784f5756dae99bc7060048e2bddf3a88c4caf48bb22abe67a3fdfc573844f6e1d71357841cfe15",
        "b61ef81dbf2a0259a020a63fc2cd210c7d415432c456c9467557debe31394a8c6633dfcf89e48474d0d49dd1c6b8fd17",
    };

    char *sha384FileTargetDigests[] =
    {
        "60c2cd773e1023affb7706a23b5ab61ef976aad94916121a24d77513c45b9f9c2a42e98979360961ec3a4ff58183f5a2",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha384MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA384");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha384FileTargetDigests),
                  "Mismatched number of files and target digests for SHA384");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha512Context = SHA2_HashStringSHA384(Messages[i]);
        EvaluateResult(Messages[i], sha384MessageTargetDigests[i], sha512Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha512Context = SHA2_HashFileSHA384(Filenames[i]);
        EvaluateResult(Filenames[i], sha384FileTargetDigests[i], sha512Context.DigestStr);
    }

    printf("\n");

    printf("SHA512 hash tests:\n");

    char *sha512MessageTargetDigests[] =
    {
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        "cb14e3f5584693bfa1deaa5e979b0e5bebe543946f97f68e17db6ba223cea3526ec5dc6a3f3cea330b9638260ccaa31669e7cb8231453ac31e6ee8f54cf9c478",
        "ecb6e7fcae5ef6fe6c23c634d60d590e5d20bd514473038debcc4aa84683d1eb95027ea407eda262bb93f0606fb0231f6970354b8c66e7fb44cdf3a86d8007bd",
    };

    char *sha512FileTargetDigests[] =
    {
        "d670ba580098ecff62c0268cee064e4109a12b4b6a02c83752789c0fbcc2a0edc7e261c6e32c878a4f1b9267645ddfd9b4b415d751199d989735c40643162d23",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    };

    hashutil_static_assert(ArrayCount(Messages) == ArrayCount(sha512MessageTargetDigests),
                  "Mismatched number of messages and target digests for SHA512");

    hashutil_static_assert(ArrayCount(Filenames) == ArrayCount(sha512FileTargetDigests),
                  "Mismatched number of files and target digests for SHA512");

    // Test string hashing
    for (int i = 0; i < ArrayCount(Messages); ++i)
    {
        sha512Context = SHA2_HashStringSHA512(Messages[i]);
        EvaluateResult(Messages[i], sha512MessageTargetDigests[i], sha512Context.DigestStr);
    }

    // Test file hashing
    for (int i = 0; i < ArrayCount(Filenames); ++i)
    {
        sha512Context = SHA2_HashFileSHA512(Filenames[i]);
        EvaluateResult(Filenames[i], sha512FileTargetDigests[i], sha512Context.DigestStr);
    }

    printf("\n");
}

int main()
{
    PerformMD5Tests();
    PerformSHA1Tests();
    PerformSHA256Tests();
    PerformSHA512Tests();

    if (!ALL_TESTS_PASSED)
    {
        printf("FAIL: %i out of %i tests failed", FAILING_TESTS, (PASSING_TESTS + FAILING_TESTS));
        return 1;
    }

    printf("SUCCESS: %i out of %i tests succeeded", PASSING_TESTS, (PASSING_TESTS + FAILING_TESTS));
    return 0;
}
