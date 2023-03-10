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
    }
#endif

    // Note (Aaron): SHA1 Tests
#if 1
    {
        sha1_context result = {};
        char *messagePtr = (char *)"";
        char *targetDigest = {};

        messagePtr = (char *)"abcde";
        targetDigest = (char *)"34aa973cd4c4daa4f61eeb2bdbad27316534016f";
        result = SHA1HashString(messagePtr);
    }
#endif

    return 0;
}
