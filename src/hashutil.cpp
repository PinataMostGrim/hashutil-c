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
    uint8 *MessagePtr = 0;
    uint32 MessageLengthBits = 0;
    uint32 PaddingLengthBits = 0;
    uint32 TotalLengthBits = 0;
    char Digest[33] = {};
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


internal void
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

    // Generate sin table T
    uint32 T[65] = {};
    for (int i = 0; i < 65; ++i)
    {
        double s = sin(i);
        s = s < 0 ? s * -1 : s;
        T[i] = uint32(s * 4294967296);
    }

    uint32 X[16] = {};

    for (uint32 i = 0;
         (i * 16) < (message->TotalLengthBits / 8);
         i++)
    {
        for (int j = 0; j < 16; ++j)
        {
            X[j] = *(message->MessagePtr + (i * 16) + j);
        }

        // Snapshot initial state of buffers
        uint32 AA = A;
        uint32 BB = B;
        uint32 CC = C;
        uint32 DD = D;

        // Perform transformations
        // Round 1
        A = MD5TransformFF(A, B, C, D, X[0], 7, T[1]);
        D = MD5TransformFF(D, A, B, C, X[1], 12, T[2]);
        C = MD5TransformFF(C, D, A, B, X[2], 17, T[3]);
        B = MD5TransformFF(B, C, D, A, X[3], 22, T[4]);

        A = MD5TransformFF(A, B, C, D, X[4], 7, T[5]);
        D = MD5TransformFF(D, A, B, C, X[5], 12, T[6]);
        C = MD5TransformFF(C, D, A, B, X[6], 17, T[7]);
        B = MD5TransformFF(B, C, D, A, X[7], 22, T[8]);

        A = MD5TransformFF(A, B, C, D, X[8], 7, T[9]);
        D = MD5TransformFF(D, A, B, C, X[9], 12, T[10]);
        C = MD5TransformFF(C, D, A, B, X[10], 17, T[11]);
        B = MD5TransformFF(B, C, D, A, X[11], 22, T[12]);

        A = MD5TransformFF(A, B, C, D, X[12], 7, T[13]);
        D = MD5TransformFF(D, A, B, C, X[13], 12, T[14]);
        C = MD5TransformFF(C, D, A, B, X[14], 17, T[15]);
        B = MD5TransformFF(B, C, D, A, X[15], 22, T[16]);

        // Round 2
        A = MD5TransformGG(A, B, C, D, X[1], 5, T[17]);
        D = MD5TransformGG(D, A, B, C, X[6], 9, T[18]);
        C = MD5TransformGG(C, D, A, B, X[11], 14, T[19]);
        B = MD5TransformGG(B, C, D, A, X[0], 20, T[20]);

        A = MD5TransformGG(A, B, C, D, X[5], 5, T[21]);
        D = MD5TransformGG(D, A, B, C, X[10],9, T[22]);
        C = MD5TransformGG(C, D, A, B, X[15], 14, T[23]);
        B = MD5TransformGG(B, C, D, A, X[4], 20, T[24]);

        A = MD5TransformGG(A, B, C, D, X[9], 5, T[25]);
        D = MD5TransformGG(D, A, B, C, X[14],9, T[26]);
        C = MD5TransformGG(C, D, A, B, X[3], 14, T[27]);
        B = MD5TransformGG(B, C, D, A, X[8], 20, T[28]);

        A = MD5TransformGG(A, B, C, D, X[13], 5, T[29]);
        D = MD5TransformGG(D, A, B, C, X[2], 9, T[30]);
        C = MD5TransformGG(C, D, A, B, X[7], 14, T[31]);
        B = MD5TransformGG(B, C, D, A, X[12], 20, T[32]);

        // Round 3
        A = MD5TransformHH(A, B, C, D, X[5], 4, T[33]);
        D = MD5TransformHH(D, A, B, C, X[8], 11, T[34]);
        C = MD5TransformHH(C, D, A, B, X[11], 16, T[35]);
        B = MD5TransformHH(B, C, D, A, X[14], 23, T[36]);

        A = MD5TransformHH(A, B, C, D, X[1], 4, T[37]);
        D = MD5TransformHH(D, A, B, C, X[4], 11, T[38]);
        C = MD5TransformHH(C, D, A, B, X[7], 16, T[39]);
        B = MD5TransformHH(B, C, D, A, X[10], 23, T[40]);

        A = MD5TransformHH(A, B, C, D, X[13], 4, T[41]);
        D = MD5TransformHH(D, A, B, C, X[0], 11, T[42]);
        C = MD5TransformHH(C, D, A, B, X[3], 16, T[43]);
        B = MD5TransformHH(B, C, D, A, X[6], 23, T[44]);

        A = MD5TransformHH(A, B, C, D, X[9], 4, T[45]);
        D = MD5TransformHH(D, A, B, C, X[12], 11, T[46]);
        C = MD5TransformHH(C, D, A, B, X[15], 16, T[47]);
        B = MD5TransformHH(B, C, D, A, X[2], 23, T[48]);

        // Round 4
        A = MD5TransformII(A, B, C, D, X[0], 6, T[49]);
        D = MD5TransformII(D, A, B, C, X[7], 10, T[50]);
        C = MD5TransformII(C, D, A, B, X[14], 15, T[51]);
        B = MD5TransformII(B, C, D, A, X[5], 21, T[52]);

        A = MD5TransformII(A, B, C, D, X[12], 6, T[53]);
        D = MD5TransformII(D, A, B, C, X[3], 10, T[54]);
        C = MD5TransformII(C, D, A, B, X[10], 15, T[55]);
        B = MD5TransformII(B, C, D, A, X[1], 21, T[56]);

        A = MD5TransformII(A, B, C, D, X[8], 6, T[57]);
        D = MD5TransformII(D, A, B, C, X[15], 10, T[58]);
        C = MD5TransformII(C, D, A, B, X[6], 15, T[59]);
        B = MD5TransformII(B, C, D, A, X[13], 21, T[60]);

        A = MD5TransformII(A, B, C, D, X[4], 6, T[61]);
        D = MD5TransformII(D, A, B, C, X[11], 10, T[62]);
        C = MD5TransformII(C, D, A, B, X[2], 15, T[63]);
        B = MD5TransformII(B, C, D, A, X[9], 21, T[64]);

        A = A + AA;
        B = B + BB;
        C = C + CC;
        D = D + DD;
    }

    sprintf_s(message->Digest, 33, "%x%x%x%x", A, B, C, D);
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

    GetMD5Hash(&message);
    printf("%s\n", message.Digest);

    return returnCode;
}
