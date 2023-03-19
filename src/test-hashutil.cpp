#include <string.h>

#include "hashutil.h"
#include "md5.h"
#include "sha1.h"


internal void
EvaluateResult(char *messagePtr, char *targetDigest, char *digestStr)
{
    if (strcmp(digestStr, targetDigest) == 0)
    {
        printf("SUCCEEDED: '%s' (%s)\n", messagePtr, digestStr);
    }
    else
    {
        printf("FAILED: '%s'\n", messagePtr);
        printf("\tExpected '%s' but received '%s'\n", targetDigest, digestStr);
    }
}


int main()
{
    // Note (Aaron): MD5 Tests
#if 1
    {
        printf("MD5 hash tests:\n");

        md5_context result = {};
        char *messagePtr = (char *)"";
        char *targetDigest = {};

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

        sha1_context result = {};
        char *messagePtr = (char *)"";
        char *targetDigest = {};

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

    return 0;
}
