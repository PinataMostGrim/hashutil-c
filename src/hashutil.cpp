#include <string.h>

#include "hashutil.h"
#include "md5.h"

global_variable int MAX_ARGS = 2;


int main(int argc, char const *argv[])
{
    // Process command line arguments
    bool processOptionalArgs = true;
    bool fileFlag = false;
    bool messageConsumed = false;
    char *messagePtr = (char *)argv[0];

    for (int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "--") == 0)
        {
            processOptionalArgs = false;
            continue;
        }

        if (processOptionalArgs
         && ((strncmp(argv[i], "-f", 2) == 0) || (strncmp(argv[i], "--file", 6) == 0)))
        {
            fileFlag = true;
            continue;
        }

        if(!messageConsumed)
        {
            messagePtr = (char *)argv[i];
            messageConsumed = true;
        }
    }

    // Error out on invalid arguments
    int argCount = argc - 1;
    if (argCount == 0)
    {
        printf("Error: Incorrect number of command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
        return EXIT_FAILURE;
    }

    if(!messageConsumed)
    {
        printf("Message argument missing");
        return EXIT_FAILURE;
    }

    if (argCount > MAX_ARGS)
    {
        printf("Warning: Too many command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
    }


    md5_context result = {};
    if(fileFlag)
    {
        printf("Calculating MD5 hash for file \"%s\":\n", messagePtr);
        result = MD5HashFile(messagePtr);
    }
    else
    {
        printf("Calculating MD5 hash for string \"%s\":\n", messagePtr);
        result = MD5HashString(messagePtr);
    }

    printf("%s\n", result.DigestStr);


#if HASHUTIL_SLOW
    // Note (Aaron): Debug code only, remove after testing is completed
    if(strcmp((char *)messagePtr, "") == 0)
    {
        char target[33] = "d41d8cd98f00b204e9800998ecf8427e";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

    if(strcmp((char *)messagePtr, "a") == 0)
    {
        char target[33] = "0cc175b9c0f1b6a831c399e269772661";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

    if(strcmp((char *)messagePtr, "The quick brown fox jumps over the lazy dog") == 0)
    {
        char target[33] = "9e107d9d372bb6826bd81d3542a419d6";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

    // Note (Aaron): Test message that is greater than 64 bytes but has a remainder less than 56 bytes long
    if(strcmp((char *)messagePtr, "The quick brown fox jumps over the lazy dog over and over and over and over and over again") == 0)
    {
        char target[33] = "3ee09c8a8bb31c3e275cd5143ea0f79a";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

    // Note (Aaron): Test message one byte less than the 56 bytes boundary
    if(strcmp((char *)messagePtr, "The quick brown fox jumps over the lazy dog over and ov") == 0)
    {
        char target[33] = "ed1b637d9fc34800ecaf4e50095f382d";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

    // Note (Aaron): Test message with remainder greater than 56 bytes long
    if(strcmp((char *)messagePtr, "The quick brown fox jumps over the lazy dog over and over and over and over and over and over and over and over and over again") == 0)
    {
        char target[33] = "e6cc782eea06cd67bf26125785ea805e";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

    if(fileFlag && strcmp(messagePtr, "test.txt") == 0)
    {
        char target[33] = "05831eb88a34bfe953de0afc2b43f46d";
        Assert(strcmp(result.DigestStr, target) == 0);
    }

#endif

    return EXIT_SUCCESS;
}
