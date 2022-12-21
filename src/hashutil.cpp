
#include "hashutil.h"
#include "md5.h"

global_variable int MAX_ARGS = 1;


int main(int argc, char const *argv[])
{
    int returnCode = 0;
    int argCount = argc - 1;
    if (argc == 1)
    {
        printf("Error: Incorrect number of command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
        return 2;
    }

    if (argCount > MAX_ARGS)
    {
        printf("Warning: Too many command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
        returnCode = 1;
    }

    unsigned char *messagePtr = (unsigned char *)argv[1];


    md5_context result = MD5HashString(messagePtr);
    printf("%s\n", result.DigestStr);

    return returnCode;
}
