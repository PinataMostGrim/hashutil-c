#include <string.h>

#include "hashutil.h"
#include "md5.h"
#include "sha1.h"


internal void
PrintUsage()
{
    printf("usage: hashutil [-f] algorithm message\n\n");
    printf("Produces a message or file digest using various hashing algorithms.\n\n");

    printf("positional arguments:\n");
    printf("  algorithm\t\tHashing algorithm to use\n");
    printf("  message\t\tMessage to hash\n");
    printf("\n");

    printf("options:\n");
    printf("-f, --file\t\tHashes a file. Message is treated as a path.\n");
    printf("\n");
}


int main(int argc, char const *argv[])
{
    // Process command line arguments
    bool processOptionalArgs = true;
    bool usageFlag = false;
    bool fileFlag = false;
    bool algorithmConsumed = false;
    char *algorithmPtr = (char *)"";
    bool messageConsumed = false;
    char *messagePtr = (char *)"";

    for (int i = 1; i < argc; ++i)
    {
        if ((strncmp(argv[i], "-h", 2) == 0) || (strncmp(argv[i], "--help", 6) == 0))
        {
            usageFlag = true;
            break;
        }

        if (strcmp(argv[i], "--") == 0)
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

        if (!algorithmConsumed)
        {
            algorithmPtr = (char *)argv[i];
            algorithmConsumed = true;
            continue;
        }

        if (!messageConsumed)
        {
            messagePtr = (char *)argv[i];
            messageConsumed = true;
            continue;
        }
    }

    if (usageFlag)
    {
        PrintUsage();
        return 0;
    }

    // Error out on missing or invalid arguments
    if (!algorithmConsumed)
    {
        printf("'algorithm' argument missing\n\n");
        PrintUsage();
        return 1;
    }

    if(!messageConsumed)
    {
        printf("'message' argument missing\n\n");
        PrintUsage();
        return 1;
    }

    // Switch on algorithm selected
    if (strcmp(algorithmPtr, "md5") == 0)
    {
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
    }
    else if (strcmp(algorithmPtr, "sha1") == 0)
    {
        sha1_context result = {};
        if(fileFlag)
        {
            printf("Calculating SHA1 hash for file \"%s\":\n", messagePtr);
            result = SHA1HashFile(messagePtr);
        }
        else
        {
            printf("Calculating SHA1 hash for string \"%s\":\n", messagePtr);
            result = SHA1HashString(messagePtr);
        }

        printf("%s\n", result.DigestStr);
    }
    else
    {
        printf("Unsupported algorithm selected\n");
        return 1;
    }

    return 0;
}
