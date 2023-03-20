#include <string.h>

#include "hashutil.h"
#include "md5.h"

global_variable int MAX_ARGS = 2;

internal void
PrintUsage()
{
    printf("usage: hashutil [-f] message\n\n");
    printf("Produces a message or file digest using various hashing algorithms.\n\n");

    printf("positional arguments:\n");
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

        if(!messageConsumed)
        {
            messagePtr = (char *)argv[i];
            messageConsumed = true;
        }
    }

    if (usageFlag)
    {
        PrintUsage();
        return 0;
    }

    // Error out on invalid arguments
    int argCount = argc - 1;
    if ((argCount == 0) || (argCount > MAX_ARGS))
    {
        printf("Error: Incorrect number of command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
        PrintUsage();

        return 1;
    }

    if(!messageConsumed)
    {
        printf("'Message' argument missing\n\n");
        return 1;
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

    return EXIT_SUCCESS;
}
