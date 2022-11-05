#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "hashutil.h"


#define internal static
#define global_variable static


typedef uint8_t uint8;
typedef uint32_t uint32;
typedef uint64_t uint64;


global_variable int MAX_ARGS = 1;


struct message
{
    uint8 *MessagePtr;
    uint32 MessageLengthBits;
    uint32 PaddingLengthBits;
    uint32 TotalLengthBits;
};


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


internal void
MemoryCopy(const uint8 *source, uint8 *destination, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(destination + i) = *(source + i);
    }
}


internal uint32
GetMD5PaddingLengthBits(uint32 messageLengthBits)
{
    uint32 modulo = messageLengthBits % 512;
    uint32 paddingLength = modulo < 448 ? 448 - modulo : (448 + 512) - modulo;

    Assert(modulo + paddingLength == 448);

    return paddingLength;
}


internal char*
GetMD5Hash(message *message)
{
    // Apply 1 padding to message
    uint8 *paddingPtr = message->MessagePtr + (message->MessageLengthBits / 8);
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply 0 padding to message
    uint8 *paddingEndPtr = message->MessagePtr + (message->MessageLengthBits / 8) + (message->PaddingLengthBits / 8);
    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append the length of the message as a 64-bit representation
    uint64 *sizePtr = (uint64 *)paddingPtr;
    *sizePtr = (uint64)message->TotalLengthBits;

    // Initialize MD buffers
    uint32 A = (0x01 << 24) | (0x23 << 16) | (0x45 << 8) | (0x67 << 0);
    uint32 B = (0x89 << 24) | (0xAB << 16) | (0xCD << 8) | (0xEF << 0);
    uint32 C = (0xfe << 24) | (0xdc << 16) | (0xba << 8) | (0x98 << 0);
    uint32 D = (0x76 << 24) | (0x54 << 16) | (0x32 << 8) | (0x10 << 0);

    uint32 *BufferA = &A;
    uint32 *BufferB = &B;
    uint32 *BufferC = &C;
    uint32 *BufferD = &D;


    return (char *)"";
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
    message message = {};
    message.MessageLengthBits = GetStringLengthBits(messagePtr);

    // Get the padded size of the message
    message.PaddingLengthBits = GetMD5PaddingLengthBits(message.MessageLengthBits);
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
    MemoryCopy((uint8 *)messagePtr, (uint8 *)message.MessagePtr, (message.TotalLengthBits / 8));

    char *hash = GetMD5Hash(&message);
    printf("hash - %s\n", hash);

    return returnCode;
}
