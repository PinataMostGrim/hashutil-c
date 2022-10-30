#include <stdio.h>
#include "hashutil.h"

#define internal static
#define global_variable static

global_variable int MAX_ARGS = 1;


internal int
GetStringLengthBits(char *string)
{
    int result = 0;
    while (*string != 0x00)
    {
        string++;
        result++;
    }

    return result * 8;
}

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

    // Get the size of the message in bits
    {
        int messageLengthBits = GetStringLengthBits((char *)argv[1]);
        printf("Message length: %i", messageLengthBits);
    }

    // Alternatively use standard library:
    // {
    //     int messageLengthBytes = strlen(argv[1]);
    //     printf("Message length: %i", messageLengthBytes);
    // }

    return returnCode;
}
