
#include "hashutil.h"
#include "md5.h"

global_variable int MAX_ARGS = 1;


int main(int argc, char const *argv[])
{
    int argCount = argc - 1;
    if (argc == 1)
    {
        printf("Error: Incorrect number of command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
        return EXIT_FAILURE;
    }

    if (argCount > MAX_ARGS)
    {
        printf("Warning: Too many command line arguments supplied; expected %i but received %i\n", MAX_ARGS, argCount);
    }

    char *messagePtr = (char *)argv[1];


    md5_context result = MD5HashString(messagePtr);
    printf("%s\n", result.DigestStr);

    return EXIT_SUCCESS;
}
