#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

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
MD5GetPaddingLengthBits(uint32 messageLengthBits)
{
    uint32 modulo = messageLengthBits % 512;
    uint32 paddingLength = modulo < 448 ? 448 - modulo : (448 + 512) - modulo;

    Assert(modulo + paddingLength == 448);

    return paddingLength;
}


internal uint32
MD5AuxF(uint32 x, uint32 y, uint32 z)
{
    // Function F(X,Y,Z) = XY v not(X) Z
    uint32 result = (x & y) | (~x & z);
    return result;
}


internal uint32
MD5AuxG(uint32 x, uint32 y, uint32 z)
{
    // Function G(X,Y,Z) = XZ v Y not(Z)
    uint32 result = (x & z) | (y & ~z);
    return result;
}


internal uint32
MD5AuxH(uint32 x, uint32 y, uint32 z)
{
    // Function H(X,Y,Z) = X xor Y xor Z
    uint32 result = (x ^ y ^ z);
    return result;
}


internal uint32
MD5AuxI(uint32 x, uint32 y, uint32 z)
{
    // Function I(X,Y,Z) = Y xor (X v not(Z))
    uint32 result = y ^ (x | ~z);
    return result;
}


internal uint32
MD5RotateLeft(uint32 x, int s)
{
    return (x << s) | (x >> (32-s));
}

internal uint32
MD5TransformFF(uint32 A, uint32 B, uint32 C, uint32 D, uint32 X, int S, uint32 T)
{
    // a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
    uint32 result = A + MD5AuxF(B, C, D) + X + T;
    result = MD5RotateLeft(result, S);
    return B + result;
}


internal uint32
MD5TransformGG(uint32 A, uint32 B, uint32 C, uint32 D, uint32 X, int S, uint32 T)
{
    // a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
    uint32 result = A + MD5AuxG(B, C, D) + X + T;
    result = MD5RotateLeft(result, S);
    return B + result;
}


internal uint32
MD5TransformHH(uint32 A, uint32 B, uint32 C, uint32 D, uint32 X, int S, uint32 T)
{
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
    uint32 result = A + MD5AuxH(B, C, D) + X + T;
    result = MD5RotateLeft(result, S);
    return B + result;
}


internal uint32
MD5TransformII(uint32 A, uint32 B, uint32 C, uint32 D, uint32 X, int S, uint32 T)
{
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
    uint32 result = A + MD5AuxI(B, C, D) + X + T;
    result = MD5RotateLeft(result, S);
    return B + result;
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
    uint32 A = 0x67452301;
    uint32 B = 0xefcdab89;
    uint32 C = 0x98badcfe;
    uint32 D = 0x10325476;

    uint32 *BufferA = &A;
    uint32 *BufferB = &B;
    uint32 *BufferC = &C;
    uint32 *BufferD = &D;

    // Generate sin table T
    uint32 T[64] = {};
    for (int i = 0; i < 64; ++i)
    {
        double s = sin(i + 1);
        s = s < 0 ? s * -1 : s;
        T[i] = uint32(s * 4294967296);
    }

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
    MemoryCopy((uint8 *)messagePtr, (uint8 *)message.MessagePtr, (message.TotalLengthBits / 8));

    char *hash = GetMD5Hash(&message);
    printf("hash - %s\n", hash);

    return returnCode;
}
