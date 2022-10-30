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

internal int
MD5GetPaddingLengthBits(int messageLengthBits)
{
    int modulo = messageLengthBits % 512;
    int paddingLength = modulo < 448 ? 448 - modulo : (448 + 512) - modulo;

    Assert(messageLengthBits + paddingLength == 448);

    return paddingLength;
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

    // char *messagePtr = (char *)argv[1];
    char *messagePtr = (char *)"The quick brown fox jumped over the lazy dog";

    // Get the size of the message in bits
    int messageLengthBits = GetStringLengthBits(messagePtr);
    // Alternatively use standard library:
    // int messageLengthBytes = strlen(argv[1]);

    // Get the padded size of the message
    int paddingLength = MD5GetPaddingLengthBits(messageLengthBits);
    printf("For a message length of '%i' bits, use a padding length of %i bits", messageLengthBits, paddingLength);

    Assert(paddingLength == 96);

    return returnCode;
}
