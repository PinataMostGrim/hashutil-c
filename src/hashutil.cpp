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

    return EXIT_SUCCESS;
}
