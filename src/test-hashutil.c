#include <stdio.h>
#include <assert.h>

#define HASHUTIL_MD5_IMPLEMENTATION
#include "md5.h"
#define HASHUTIL_SHA1_IMPLEMENTATION
#include "sha1.h"
#define HASHUTIL_SHA2_IMPLEMENTATION
#include "sha2.h"


static void EvaluateResult(char *messagePtr, char *targetDigest, char *digestStr)
{
    if (strcmp(digestStr, targetDigest) == 0)
    {
        printf("SUCCEEDED: '%s' [%s]\n", messagePtr, digestStr);
    }
    else
    {
        printf("FAILED: '%s'\n", messagePtr);
        printf("\tExpected:\t%s\n", targetDigest);
        printf("\tReceived:\t%s\n", digestStr);
    }
}


int main()
{
    char *messages[] =
    {
        "",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "The quick brown fox jumps over the lazy dog over and ove",
        "The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again",
    };

    char *filenames[] =
    {
        "etc/test.txt",
        "etc/test2.txt",
    };

    // Note (Aaron): MD5 Tests
#if 1
    {
        printf("MD5 hash tests:\n");

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

        static_assert(ArrayCount(messages) == ArrayCount(md5MessageTargetDigests),
                      "Mismatched number of messages and target digests for MD5");

        static_assert(ArrayCount(filenames) == ArrayCount(md5FileTargetDigests),
                      "Mismatched number of files and target digests for MD5");

        // Test string hashing
        md5_context md5Context;
        for (int i = 0; i < ArrayCount(messages); ++i)
        {
            md5Context = MD5HashString(messages[i]);
            EvaluateResult(messages[i], md5MessageTargetDigests[i], md5Context.DigestStr);
        }

        // Test file hashing
        for (int i = 0; i < ArrayCount(filenames); ++i)
        {
            md5Context = MD5HashFile(filenames[i]);
            EvaluateResult(filenames[i], md5FileTargetDigests[i], md5Context.DigestStr);
        }

        printf("\n");
    }
#endif

    // Note (Aaron): SHA1 Tests
#if 1
    {
        printf("SHA1 hash tests:\n");

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

        static_assert(ArrayCount(messages) == ArrayCount(sha1MessageTargetDigests),
                      "Mismatched number of messages and target digests for SHA1");

        static_assert(ArrayCount(filenames) == ArrayCount(sha1FileTargetDigests),
                      "Mismatched number of files and target digests for SHA1");

        // Test string hashing
        sha1_context sha1Context;
        for (int i = 0; i < ArrayCount(messages); ++i)
        {
            sha1Context = SHA1HashString(messages[i]);
            EvaluateResult(messages[i], sha1MessageTargetDigests[i], sha1Context.DigestStr);
        }

        // Test file hashing
        for (int i = 0; i < ArrayCount(filenames); ++i)
        {
            sha1Context = SHA1HashFile(filenames[i]);
            EvaluateResult(filenames[i], sha1FileTargetDigests[i], sha1Context.DigestStr);
        }

        printf("\n");
    }
#endif

    // Note (Aaron): SHA256 Tests
#if 1
    {
        printf("SHA224 hash tests:\n");

        char *sha224MessageTargetDigests[] =
        {
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            "b5b48277b755e58a7ef4b3f759020696beeb77684ae4e6f8d6f113ed",
            "9e04184fee6c5497488121d85dd19df057a05aae5e1bac5a17789fe8",
        };

        static_assert(ArrayCount(messages) == ArrayCount(sha224MessageTargetDigests),
                      "Mismatched number of messages and target digests for SHA224");

        // Hash strings
        sha2_256_context sha256Context;
        for (int i = 0; i < ArrayCount(messages); ++i)
        {
            sha256Context = SHA2_HashStringSHA256(messages[i], SHA2_SHA256_224);
            EvaluateResult(messages[i], sha224MessageTargetDigests[i], sha256Context.DigestStr);
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

        static_assert(ArrayCount(messages) == ArrayCount(sha256MessageTargetDigests),
                      "Mismatched number of messages and target digests for SHA256");

        // Test string hashing
        for (int i = 0; i < ArrayCount(messages); ++i)
        {
            sha256Context = SHA2_HashStringSHA256(messages[i], SHA2_SHA256_256);
            EvaluateResult(messages[i], sha256MessageTargetDigests[i], sha256Context.DigestStr);
        }

        printf("\n");
    }
#endif

#if 1
    {
        printf("SHA384 hash tests:\n");

        char *sha384MessageTargetDigests[] =
        {
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            "f05d0f630e9e2c38d9784f5756dae99bc7060048e2bddf3a88c4caf48bb22abe67a3fdfc573844f6e1d71357841cfe15",
            "b61ef81dbf2a0259a020a63fc2cd210c7d415432c456c9467557debe31394a8c6633dfcf89e48474d0d49dd1c6b8fd17",
        };

        static_assert(ArrayCount(messages) == ArrayCount(sha384MessageTargetDigests),
                      "Mismatched number of messages and target digests for SHA384");

        // Test string hashing
        sha2_512_context sha512Context;
        for (int i = 0; i < ArrayCount(messages); ++i)
        {
            sha512Context = SHA2_HashStringSHA512(messages[i], SHA2_SHA512_384);
            EvaluateResult(messages[i], sha384MessageTargetDigests[i], sha512Context.DigestStr);
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

        static_assert(ArrayCount(messages) == ArrayCount(sha512MessageTargetDigests),
                      "Mismatched number of messages and target digests for SHA512");

        // Test string hashing
        for (int i = 0; i < ArrayCount(messages); ++i)
        {
            sha512Context = SHA2_HashStringSHA512(messages[i], SHA2_SHA512_512);
            EvaluateResult(messages[i], sha512MessageTargetDigests[i], sha512Context.DigestStr);
        }

        printf("\n");
    }
#endif

    return 0;
}
