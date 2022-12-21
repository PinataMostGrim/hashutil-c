#if !defined(MD5_H)

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "hashutil.h"


struct md5_context
{
    uint32 MessageLengthBits = 0;
    uint32 State[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    uint8 Digest[16] = {};
    char DigestStr[33] = {};
};


// Note (Aaron): This is a naive implementation
internal void
MemoryCopy(const uint8 *source, uint8 *destination, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(destination + i) = *(source + i);
    }
}


internal void
MemoryZero(uint8 *ptr, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(ptr + i) = 0;
    }
}



// #define MD5AuxF(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
internal uint32
MD5AuxF(uint32 x, uint32 y, uint32 z)
{
    // Function F(X,Y,Z) = XY v not(X) Z
    uint32 result = (x & y) | (~x & z);
    return result;
}


// #define MD5AuxG(X, Y, Z) (((X) & (Z)) | ((Y) & (~Z)))
internal uint32
MD5AuxG(uint32 x, uint32 y, uint32 z)
{
    // Function G(X,Y,Z) = XZ v Y not(Z)
    uint32 result = (x & z) | (y & ~z);
    return result;
}


// #define MD5AuxH(X, Y, Z) ((X) ^ (Y) ^ (Z))
internal uint32
MD5AuxH(uint32 x, uint32 y, uint32 z)
{
    // Function H(X,Y,Z) = X xor Y xor Z
    uint32 result = (x ^ y ^ z);
    return result;
}


// #define MD5AuxI(X, Y, Z) ((Y) ^ ((X) | (~Z)))
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
MD5UpdateHash(md5_context *context, unsigned char *ptr, uint32 byteLength)
{
    // Assert that the block length is divisible by 64 bytes
    Assert(byteLength % 64 == 0);

    uint32 block[16] = {};

    // Generate sin table T
    uint32 T[65] = {};
    for (int i = 0; i < 65; ++i)
    {
        double s = sin(i);
        s = s < 0 ? s * -1 : s;
        T[i] = uint32(s * 4294967296);
    }

    // Note (Aaron): Iterate over 64 byte blocks of the data
    // 'i' represents the byte position in the data
    for (uint32 i = 0;
         i < (byteLength);
         i+=64)
    {
        for (int j = 0; j < 16; ++j)
        {
            // Note (Aaron): This will work regardless of endianness
            block[j] = (uint32)(*(ptr + i + (j * 4)))
                | (uint32)(*(ptr + i + (j * 4) + 1) << 8)
                | (uint32)(*(ptr + i + (j * 4) + 2) << 16)
                | (uint32)(*(ptr + i + (j * 4) + 3) << 24);

            // Note (Aaron): This will only work on little-endian systems (with no alignment restrictions)
            // uint32 endianness = 0xdeadbeef;
            // Assert((*(unsigned char *)&endianness) == 0xef)
            // block[j] = *(uint32 *)((context->MessagePtr + i + (j * 4)));
        }

        uint32 A = context->State[0];
        uint32 B = context->State[1];
        uint32 C = context->State[2];
        uint32 D = context->State[3];

        // Perform transformations
        // Round 1
        A = MD5TransformFF(A, B, C, D, block[0], 7, T[1]);
        D = MD5TransformFF(D, A, B, C, block[1], 12, T[2]);
        C = MD5TransformFF(C, D, A, B, block[2], 17, T[3]);
        B = MD5TransformFF(B, C, D, A, block[3], 22, T[4]);

        A = MD5TransformFF(A, B, C, D, block[4], 7, T[5]);
        D = MD5TransformFF(D, A, B, C, block[5], 12, T[6]);
        C = MD5TransformFF(C, D, A, B, block[6], 17, T[7]);
        B = MD5TransformFF(B, C, D, A, block[7], 22, T[8]);

        A = MD5TransformFF(A, B, C, D, block[8], 7, T[9]);
        D = MD5TransformFF(D, A, B, C, block[9], 12, T[10]);
        C = MD5TransformFF(C, D, A, B, block[10], 17, T[11]);
        B = MD5TransformFF(B, C, D, A, block[11], 22, T[12]);

        A = MD5TransformFF(A, B, C, D, block[12], 7, T[13]);
        D = MD5TransformFF(D, A, B, C, block[13], 12, T[14]);
        C = MD5TransformFF(C, D, A, B, block[14], 17, T[15]);
        B = MD5TransformFF(B, C, D, A, block[15], 22, T[16]);

        // Round 2
        A = MD5TransformGG(A, B, C, D, block[1], 5, T[17]);
        D = MD5TransformGG(D, A, B, C, block[6], 9, T[18]);
        C = MD5TransformGG(C, D, A, B, block[11], 14, T[19]);
        B = MD5TransformGG(B, C, D, A, block[0], 20, T[20]);

        A = MD5TransformGG(A, B, C, D, block[5], 5, T[21]);
        D = MD5TransformGG(D, A, B, C, block[10],9, T[22]);
        C = MD5TransformGG(C, D, A, B, block[15], 14, T[23]);
        B = MD5TransformGG(B, C, D, A, block[4], 20, T[24]);

        A = MD5TransformGG(A, B, C, D, block[9], 5, T[25]);
        D = MD5TransformGG(D, A, B, C, block[14],9, T[26]);
        C = MD5TransformGG(C, D, A, B, block[3], 14, T[27]);
        B = MD5TransformGG(B, C, D, A, block[8], 20, T[28]);

        A = MD5TransformGG(A, B, C, D, block[13], 5, T[29]);
        D = MD5TransformGG(D, A, B, C, block[2], 9, T[30]);
        C = MD5TransformGG(C, D, A, B, block[7], 14, T[31]);
        B = MD5TransformGG(B, C, D, A, block[12], 20, T[32]);

        // Round 3
        A = MD5TransformHH(A, B, C, D, block[5], 4, T[33]);
        D = MD5TransformHH(D, A, B, C, block[8], 11, T[34]);
        C = MD5TransformHH(C, D, A, B, block[11], 16, T[35]);
        B = MD5TransformHH(B, C, D, A, block[14], 23, T[36]);

        A = MD5TransformHH(A, B, C, D, block[1], 4, T[37]);
        D = MD5TransformHH(D, A, B, C, block[4], 11, T[38]);
        C = MD5TransformHH(C, D, A, B, block[7], 16, T[39]);
        B = MD5TransformHH(B, C, D, A, block[10], 23, T[40]);

        A = MD5TransformHH(A, B, C, D, block[13], 4, T[41]);
        D = MD5TransformHH(D, A, B, C, block[0], 11, T[42]);
        C = MD5TransformHH(C, D, A, B, block[3], 16, T[43]);
        B = MD5TransformHH(B, C, D, A, block[6], 23, T[44]);

        A = MD5TransformHH(A, B, C, D, block[9], 4, T[45]);
        D = MD5TransformHH(D, A, B, C, block[12], 11, T[46]);
        C = MD5TransformHH(C, D, A, B, block[15], 16, T[47]);
        B = MD5TransformHH(B, C, D, A, block[2], 23, T[48]);

        // Round 4
        A = MD5TransformII(A, B, C, D, block[0], 6, T[49]);
        D = MD5TransformII(D, A, B, C, block[7], 10, T[50]);
        C = MD5TransformII(C, D, A, B, block[14], 15, T[51]);
        B = MD5TransformII(B, C, D, A, block[5], 21, T[52]);

        A = MD5TransformII(A, B, C, D, block[12], 6, T[53]);
        D = MD5TransformII(D, A, B, C, block[3], 10, T[54]);
        C = MD5TransformII(C, D, A, B, block[10], 15, T[55]);
        B = MD5TransformII(B, C, D, A, block[1], 21, T[56]);

        A = MD5TransformII(A, B, C, D, block[8], 6, T[57]);
        D = MD5TransformII(D, A, B, C, block[15], 10, T[58]);
        C = MD5TransformII(C, D, A, B, block[6], 15, T[59]);
        B = MD5TransformII(B, C, D, A, block[13], 21, T[60]);

        A = MD5TransformII(A, B, C, D, block[4], 6, T[61]);
        D = MD5TransformII(D, A, B, C, block[11], 10, T[62]);
        C = MD5TransformII(C, D, A, B, block[2], 15, T[63]);
        B = MD5TransformII(B, C, D, A, block[9], 21, T[64]);

        context->State[0] += A;
        context->State[1] += B;
        context->State[2] += C;
        context->State[3] += D;
    }

    // Zero out block[] to prevent sensitive information being left in memory
    // MemoryZero(&block, ArrayCount(block));
    for (int i = 0; i < ArrayCount(block); ++i)
    {
        block[i] = 0;
    }
}


internal void
MD5CalculateDigest(md5_context *context)
{
    // Extract digest values, convert to string, and store in context
    unsigned int i, j;
    for (i = 0, j = 0; i < 4; ++i, j+=4)
    {
        context->Digest[j] = (uint8)(context->State[i] & 0xff);
        context->Digest[j+1] = (uint8)((context->State[i] >> 8) & 0xff);
        context->Digest[j+2] = (uint8)((context->State[i] >> 16) & 0xff);
        context->Digest[j+3] = (uint8)((context->State[i] >> 24) & 0xff);

        sprintf_s(context->DigestStr + (j*2), 9,"%02x%02x%02x%02x", context->Digest[j], context->Digest[j+1], context->Digest[j+2], context->Digest[i*4+3]);
    }
}


internal md5_context
MD5HashString(unsigned char *messagePtr)
{
    md5_context result = {};
    int byteCounter = 0;

    while (*messagePtr != 0x00)
    {
        messagePtr++;
        result.MessageLengthBits += 8;
        byteCounter++;

        if(byteCounter == 64)
        {
            MD5UpdateHash(&result, messagePtr - byteCounter, byteCounter);
            byteCounter = 0;
        }
    }

    // Allocate memory to store the message remainder + padding + encoded message length
    uint8 *messageRemainterPtr;
    bool useExtendedMargine = byteCounter >= 56;

    if (!useExtendedMargine)
    {
        // Message remainder fits inside the 448 bit margine
        messageRemainterPtr = (uint8 *)malloc(64);
    }
    else
    {
        // Message remainder exceeds the 448 bit margine so we apply extra padding to wrap us back to 448
        messageRemainterPtr = (uint8 *)malloc(128);
    }

    // Copy message remainder into the allocated memory
    MemoryCopy(messagePtr - byteCounter, messageRemainterPtr, byteCounter);

    // Apply padded 1
    uint8 *paddingPtr = messageRemainterPtr + byteCounter;
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply padded 0s
    uint8 *paddingEndPtr = useExtendedMargine
        ? messageRemainterPtr + 120
        : messageRemainterPtr + 56;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append the length of the message as a 64-bit representation
    uint64 *sizePtr = (uint64 *)paddingPtr;
    *sizePtr = (uint64)result.MessageLengthBits;

    // Perform final hash update
    byteCounter = useExtendedMargine ? 128 : 64;
    Assert(byteCounter == (paddingPtr - messageRemainterPtr) + sizeof(uint64));
    MD5UpdateHash(&result, messageRemainterPtr, byteCounter);

    // Zero out message remainder to prevent sensitive information being left in memory
    MemoryZero(messageRemainterPtr, byteCounter);

    // Calculate hash and return
    MD5CalculateDigest(&result);

    return result;
}

#define MD5_H
#endif
