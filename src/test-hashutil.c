#include <string.h>
#include <stdio.h>

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
        printf("SUCCEEDED: '%s' (%s)\n", messagePtr, digestStr);
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
    // Note (Aaron): MD5 Tests
#if 1
    {
        printf("MD5 hash tests:\n");

        md5_context result;
        char *messagePtr = (char *)"";
        char *targetDigest = "";

        result = MD5HashString(messagePtr);
        targetDigest = (char *)"d41d8cd98f00b204e9800998ecf8427e";
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"a";
        targetDigest = (char *)"0cc175b9c0f1b6a831c399e269772661";
        result = MD5HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"The quick brown fox jumps over the lazy dog";
        targetDigest = (char *)"9e107d9d372bb6826bd81d3542a419d6";
        result = MD5HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        // Note (Aaron): Test message that is greater than 64 bytes but has a remainder less than 56 bytes long
        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and over and over and over and over again";
        targetDigest = (char *)"3ee09c8a8bb31c3e275cd5143ea0f79a";
        result = MD5HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        // Note (Aaron): Test message one byte less than the 56 bytes boundary
        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and ov";
        targetDigest = (char *)"ed1b637d9fc34800ecaf4e50095f382d";
        result = MD5HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        // Note (Aaron): Test message with remainder greater than 56 bytes long
        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again";
        targetDigest = (char *)"e6cc782eea06cd67bf26125785ea805e";
        result = MD5HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        char *fileNamePtr = (char *)"etc/test.txt";
        targetDigest = (char *)"05831eb88a34bfe953de0afc2b43f46d";
        result = MD5HashFile(fileNamePtr);
        EvaluateResult(fileNamePtr, targetDigest, result.DigestStr);

        fileNamePtr = (char *)"etc/test2.txt";
        targetDigest = (char *)"d41d8cd98f00b204e9800998ecf8427e";
        result = MD5HashFile(fileNamePtr);
        EvaluateResult(fileNamePtr, targetDigest, result.DigestStr);

        printf("\n");
    }
#endif

    // Note (Aaron): SHA1 Tests
#if 1
    {
        printf("SHA1 hash tests:\n");

        sha1_context result;
        char *messagePtr = (char *)"";
        char *targetDigest = "";

        messagePtr = (char *)"a";
        targetDigest = (char *)"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"abc";
        targetDigest = (char *)"a9993e364706816aba3e25717850c26c9cd0d89d";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"abcde";
        targetDigest = (char *)"03de6c570bfe24bfc328ccd7ca46b76eadaf4334";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        targetDigest = (char *)"84983e441c3bd26ebaae4aa1f95129e5e54670f1";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"0123456701234567012345670123456701234567012345670123456701234567";
        targetDigest = (char *)"e0c094e867ef46c350ef54a7f59dd60bed92ae83";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        // Message with a length of exactly 448 bits
        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and ove";
        targetDigest = (char *)"51c6df96407f4c6b257f5767247ac6b3ad71d773";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again";
        targetDigest = (char *)"b1d31797695eb0c2e369dd4149a80cbb58ba48e0";
        result = SHA1HashString(messagePtr);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        char *fileNamePtr = (char *)"etc/test.txt";
        targetDigest = (char *)"3c5a24b30b738ec655e7c1aff04743285f07d690";
        result = SHA1HashFile(fileNamePtr);
        EvaluateResult(fileNamePtr, targetDigest, result.DigestStr);

        fileNamePtr = (char *)"etc/test2.txt";
        targetDigest = (char *)"da39a3ee5e6b4b0d3255bfef95601890afd80709";
        result = SHA1HashFile(fileNamePtr);
        EvaluateResult(fileNamePtr, targetDigest, result.DigestStr);

        printf("\n");
    }
#endif

    // Note (Aaron): SHA2 Tests
#if 1
    {
        printf("SHA256 hash tests:\n");

        sha2_256_context result;
        char *messagePtr = (char *)"";
        char *targetDigest = "";

        messagePtr = (char *)"abc";
        targetDigest = (char *)"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_256);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        targetDigest = (char *)"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_256);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again";
        targetDigest = (char *)"5e471d49eef9c7f859044d9ef2d31175d94384953f842ba02e20e06b77946408";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_256);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        printf("\n");

        printf("SHA224 hash tests:\n");

        messagePtr = (char *)"";
        targetDigest = (char *)"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_224);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"abc";
        targetDigest = (char *)"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_224);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        targetDigest = (char *)"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_224);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

        messagePtr = (char *)"The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again";
        targetDigest = (char *)"9e04184fee6c5497488121d85dd19df057a05aae5e1bac5a17789fe8";
        result = SHA2_HashStringSHA256(messagePtr, SHA2_SHA256_224);
        EvaluateResult(messagePtr, targetDigest, result.DigestStr);

    }
#endif

    return 0;
}
