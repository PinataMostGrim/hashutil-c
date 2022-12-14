#include <stdlib.h>

#include "hashutil.h"
#include "md5.h"

global_variable int MAX_ARGS = 1;


// Note (Aaron): This is a naive implementation
internal uint32
GetStringLengthBits(char *string)
{
    uint32 result = 0;
    while (*string != 0x00)
    {
        string++;
        result++;
    }

    return result * 8;
}


// Note (Aaron): This is a naive implementation
internal void
MemoryCopy(const uint8 *source, uint8 *destination, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(destination + i) = *(source + i);
    }
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

    char *messagePtr = (char *)argv[1];

    // Get the size of the message in bits
    md5_context message = {};
    message.MessageLengthBits = GetStringLengthBits(messagePtr);

    // Get the padded size of the message
    message.PaddingLengthBits = MD5GetPaddingLengthBits(message.MessageLengthBits);
    message.TotalLengthBits = message.MessageLengthBits + message.PaddingLengthBits + 64;
    Assert(message.TotalLengthBits % 512 == 0);

    // Allocate memory for the padded message
    message.MessagePtr = (uint8 *)malloc(message.TotalLengthBits / 8);
    if (message.MessagePtr == 0)
    {
        printf("Error: Unable to allocate memory for message");
        return 2;
    }

    // Copy the message into the allocated memory
    MemoryCopy((uint8 *)messagePtr, (uint8 *)message.MessagePtr, (message.MessageLengthBits / 8));

    MD5GetHash(&message);
    printf("%s\n", message.DigestStr);

    return returnCode;
}
