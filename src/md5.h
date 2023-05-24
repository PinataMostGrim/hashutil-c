/* TODO (Aaron):
    - Profile the time taken hashing a large file using methods vs defines
    - Add platform layer for working with files
*/

/*  md5.h - Implements the MD5 hashing algorithm.

    Do this:
      #define HASHUTIL_MD5_IMPLEMENTATION
   before you include this file in *one* C or C++ file to create the implementation.
*/

#ifndef HASHUTIL_MD5_H
#define HASHUTIL_MD5_H

#include <stdint.h>
#include <stdbool.h>

static uint32_t const HASHUTIL_MD5_VERSION = 1;

typedef struct
{
    uint32_t MessageLengthBits;
    uint32_t State[4];
    uint8_t Digest[16];
    char DigestStr[33];
    bool Error;
    char ErrorStr[64];
} md5_context;


#ifdef __cplusplus
extern "C" {
#endif

uint32_t MD5_GetVersion();
md5_context MD5_HashString(char *messagePtr);
md5_context MD5_HashFile(const char *fileName);

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_MD5_H
// end of header file ////////////////////////////////////////////////////////


#ifdef HASHUTIL_MD5_IMPLEMENTATION

#include <stdio.h>
#include <stdbool.h>

#if HASHUTIL_SLOW
#include <assert.h>
#define md5_static_assert(expression, string) static_assert(expression, string)
#define md5_assert(expression) assert(expression)
#else
#define md5_static_assert(expression, string)
#define md5_assert(expression)
#endif

#define MD5_ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

#define MD5_MESSAGE_BLOCK_SIZE 64
#define MD5_MESSAGE_LENGTH_BLOCK_SHA256 8


#ifdef __cplusplus
extern "C" {
#endif

uint32_t MD5_GetVersion()
{
    uint32_t result = HASHUTIL_MD5_VERSION;
    return result;
}


static void *MD5_MemoryCopy(void *destPtr, void const *sourcePtr, size_t size)
{
    md5_assert(size > 0);

    unsigned char *source = (unsigned char *)sourcePtr;
    unsigned char *dest = (unsigned char *)destPtr;
    while(size--) *dest++ = *source++;

    return destPtr;
}


static void *MD5_MemorySet(uint8_t *destPtr, int c, size_t count)
{
    md5_assert(count > 0);

    unsigned char *dest = (unsigned char *)destPtr;
    while(count--) *dest++ = (unsigned char)c;

    return destPtr;
}


static void MD5_InitializeContext(md5_context *context)
{
    context->MessageLengthBits = 0;

    context->State[0] = 0x67452301;
    context->State[1] = 0xefcdab89;
    context->State[2] = 0x98badcfe;
    context->State[3] = 0x10325476;

    context->Error = false;

#if HASHUTIL_SLOW
    MD5_MemorySet(context->Digest, 0, sizeof(context->Digest));
    MD5_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    MD5_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
#endif
}


// 32-bit Circular bit shift left
static uint32_t MD5_ROTL(uint32_t value, uint8_t count)
{
    return (value << count) | (value >> (32 - count));
}


// #define MD5AuxF(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
static uint32_t MD5_AuxF(uint32_t x, uint32_t y, uint32_t z)
{
    // Function F(X,Y,Z) = XY v not(X) Z
    uint32_t result = (x & y) | (~x & z);
    return result;
}


// #define MD5AuxG(X, Y, Z) (((X) & (Z)) | ((Y) & (~Z)))
static uint32_t MD5_AuxG(uint32_t x, uint32_t y, uint32_t z)
{
    // Function G(X,Y,Z) = XZ v Y not(Z)
    uint32_t result = (x & z) | (y & ~z);
    return result;
}


// #define MD5AuxH(X, Y, Z) ((X) ^ (Y) ^ (Z))
static uint32_t MD5_AuxH(uint32_t x, uint32_t y, uint32_t z)
{
    // Function H(X,Y,Z) = X xor Y xor Z
    uint32_t result = (x ^ y ^ z);
    return result;
}


// #define MD5AuxI(X, Y, Z) ((Y) ^ ((X) | (~Z)))
static uint32_t MD5_AuxI(uint32_t x, uint32_t y, uint32_t z)
{
    // Function I(X,Y,Z) = Y xor (X v not(Z))
    uint32_t result = y ^ (x | ~z);
    return result;
}


static uint32_t MD5_TransformFF(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5_AuxF(B, C, D) + X + T;
    result = MD5_ROTL(result, S);
    return B + result;
}


static uint32_t MD5_TransformGG(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5_AuxG(B, C, D) + X + T;
    result = MD5_ROTL(result, S);
    return B + result;
}


static uint32_t MD5_TransformHH(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5_AuxH(B, C, D) + X + T;
    result = MD5_ROTL(result, S);
    return B + result;
}


static uint32_t MD5_TransformII(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5_AuxI(B, C, D) + X + T;
    result = MD5_ROTL(result, S);
    return B + result;
}


static void MD5_UpdateHash(md5_context *context, uint8_t *ptr, uint64_t byteCount)
{
    // Assert that the block length is divisible by 512 bits (64 bytes)
    md5_assert(byteCount % MD5_MESSAGE_BLOCK_SIZE == 0);

    // Create 512-bit block
    uint32_t block[16];
#if HASHUTIL_SLOW
    MD5_MemorySet((uint8_t *)block, 0xff, sizeof(block));
#endif

    // Note (Aaron): Iterate over 512-bit (64 byte) blocks of the message.
    // 'i' represents the byte position in the message.
    for (uint32_t i = 0; i < (byteCount); i+=MD5_MESSAGE_BLOCK_SIZE)
    {
        for (int j = 0; j < MD5_ArrayCount(block); ++j)
        {
            // Note (Aaron): This will work regardless of endianness
            block[j] = (uint32_t)(*(ptr + i + (j * 4)))
                | (uint32_t)(*(ptr + i + (j * 4) + 1) << 8)
                | (uint32_t)(*(ptr + i + (j * 4) + 2) << 16)
                | (uint32_t)(*(ptr + i + (j * 4) + 3) << 24);

            // Note (Aaron): This will only work on little-endian systems (with no alignment restrictions)
            // uint32_t endianness = 0xdeadbeef;
            // md5_assert((*(unsigned char *)&endianness) == 0xef)
            // block[j] = *(uint32_t *)((context->MessagePtr + i + (j * 4)));
        }

        uint32_t A = context->State[0];
        uint32_t B = context->State[1];
        uint32_t C = context->State[2];
        uint32_t D = context->State[3];

        // Perform MD5 transformations
        // Round 1
        A = MD5_TransformFF(A, B, C, D, block[0], 7, 0xd76aa478);
        D = MD5_TransformFF(D, A, B, C, block[1], 12, 0xe8c7b756);
        C = MD5_TransformFF(C, D, A, B, block[2], 17, 0x242070db);
        B = MD5_TransformFF(B, C, D, A, block[3], 22, 0xc1bdceee);

        A = MD5_TransformFF(A, B, C, D, block[4], 7, 0xf57c0faf);
        D = MD5_TransformFF(D, A, B, C, block[5], 12, 0x4787c62a);
        C = MD5_TransformFF(C, D, A, B, block[6], 17, 0xa8304613);
        B = MD5_TransformFF(B, C, D, A, block[7], 22, 0xfd469501);

        A = MD5_TransformFF(A, B, C, D, block[8], 7, 0x698098d8);
        D = MD5_TransformFF(D, A, B, C, block[9], 12, 0x8b44f7af);
        C = MD5_TransformFF(C, D, A, B, block[10], 17, 0xffff5bb1);
        B = MD5_TransformFF(B, C, D, A, block[11], 22, 0x895cd7be);

        A = MD5_TransformFF(A, B, C, D, block[12], 7, 0x6b901122);
        D = MD5_TransformFF(D, A, B, C, block[13], 12, 0xfd987193);
        C = MD5_TransformFF(C, D, A, B, block[14], 17, 0xa679438e);
        B = MD5_TransformFF(B, C, D, A, block[15], 22, 0x49b40821);

        // Round 2
        A = MD5_TransformGG(A, B, C, D, block[1], 5, 0xf61e2562);
        D = MD5_TransformGG(D, A, B, C, block[6], 9, 0xc040b340);
        C = MD5_TransformGG(C, D, A, B, block[11], 14, 0x265e5a51);
        B = MD5_TransformGG(B, C, D, A, block[0], 20, 0xe9b6c7aa);

        A = MD5_TransformGG(A, B, C, D, block[5], 5, 0xd62f105d);
        D = MD5_TransformGG(D, A, B, C, block[10],9, 0x2441453);
        C = MD5_TransformGG(C, D, A, B, block[15], 14, 0xd8a1e681);
        B = MD5_TransformGG(B, C, D, A, block[4], 20, 0xe7d3fbc8);

        A = MD5_TransformGG(A, B, C, D, block[9], 5, 0x21e1cde6);
        D = MD5_TransformGG(D, A, B, C, block[14],9, 0xc33707d6);
        C = MD5_TransformGG(C, D, A, B, block[3], 14, 0xf4d50d87);
        B = MD5_TransformGG(B, C, D, A, block[8], 20, 0x455a14ed);

        A = MD5_TransformGG(A, B, C, D, block[13], 5, 0xa9e3e905);
        D = MD5_TransformGG(D, A, B, C, block[2], 9, 0xfcefa3f8);
        C = MD5_TransformGG(C, D, A, B, block[7], 14, 0x676f02d9);
        B = MD5_TransformGG(B, C, D, A, block[12], 20, 0x8d2a4c8a);

        // Round 3
        A = MD5_TransformHH(A, B, C, D, block[5], 4, 0xfffa3942);
        D = MD5_TransformHH(D, A, B, C, block[8], 11, 0x8771f681);
        C = MD5_TransformHH(C, D, A, B, block[11], 16, 0x6d9d6122);
        B = MD5_TransformHH(B, C, D, A, block[14], 23, 0xfde5380c);

        A = MD5_TransformHH(A, B, C, D, block[1], 4, 0xa4beea44);
        D = MD5_TransformHH(D, A, B, C, block[4], 11, 0x4bdecfa9);
        C = MD5_TransformHH(C, D, A, B, block[7], 16, 0xf6bb4b60);
        B = MD5_TransformHH(B, C, D, A, block[10], 23, 0xbebfbc70);

        A = MD5_TransformHH(A, B, C, D, block[13], 4, 0x289b7ec6);
        D = MD5_TransformHH(D, A, B, C, block[0], 11, 0xeaa127fa);
        C = MD5_TransformHH(C, D, A, B, block[3], 16, 0xd4ef3085);
        B = MD5_TransformHH(B, C, D, A, block[6], 23, 0x4881d05);

        A = MD5_TransformHH(A, B, C, D, block[9], 4, 0xd9d4d039);
        D = MD5_TransformHH(D, A, B, C, block[12], 11, 0xe6db99e5);
        C = MD5_TransformHH(C, D, A, B, block[15], 16, 0x1fa27cf8);
        B = MD5_TransformHH(B, C, D, A, block[2], 23, 0xc4ac5665);

        // Round 4
        A = MD5_TransformII(A, B, C, D, block[0], 6, 0xf4292244);
        D = MD5_TransformII(D, A, B, C, block[7], 10, 0x432aff97);
        C = MD5_TransformII(C, D, A, B, block[14], 15, 0xab9423a7);
        B = MD5_TransformII(B, C, D, A, block[5], 21, 0xfc93a039);

        A = MD5_TransformII(A, B, C, D, block[12], 6, 0x655b59c3);
        D = MD5_TransformII(D, A, B, C, block[3], 10, 0x8f0ccc92);
        C = MD5_TransformII(C, D, A, B, block[10], 15, 0xffeff47d);
        B = MD5_TransformII(B, C, D, A, block[1], 21, 0x85845dd1);

        A = MD5_TransformII(A, B, C, D, block[8], 6, 0x6fa87e4f);
        D = MD5_TransformII(D, A, B, C, block[15], 10, 0xfe2ce6e0);
        C = MD5_TransformII(C, D, A, B, block[6], 15, 0xa3014314);
        B = MD5_TransformII(B, C, D, A, block[13], 21, 0x4e0811a1);

        A = MD5_TransformII(A, B, C, D, block[4], 6, 0xf7537e82);
        D = MD5_TransformII(D, A, B, C, block[11], 10, 0xbd3af235);
        C = MD5_TransformII(C, D, A, B, block[2], 15, 0x2ad7d2bb);
        B = MD5_TransformII(B, C, D, A, block[9], 21, 0xeb86d391);

        context->State[0] += A;
        context->State[1] += B;
        context->State[2] += C;
        context->State[3] += D;
    }

    // Zero out block[] to prevent sensitive information being left in memory
    MD5_MemorySet((uint8_t *)&block, 0, MD5_ArrayCount(block));
}


static void MD5_ConstructDigest(md5_context *context)
{
    // Extract digest values, convert to string, and store in context
    unsigned int i, j;
    for (i = 0, j = 0; i < 4; ++i, j+=4)
    {
        context->Digest[j] = (uint8_t)(context->State[i] & 0xff);
        context->Digest[j+1] = (uint8_t)((context->State[i] >> 8) & 0xff);
        context->Digest[j+2] = (uint8_t)((context->State[i] >> 16) & 0xff);
        context->Digest[j+3] = (uint8_t)((context->State[i] >> 24) & 0xff);

        sprintf(context->DigestStr + (j*2),
                "%02x%02x%02x%02x",
                context->Digest[j],
                context->Digest[j+1],
                context->Digest[j+2],
                context->Digest[i*4+3]);
    }
}


md5_context MD5_HashString(char *messagePtr)
{
    md5_context context;
    MD5_InitializeContext(&context);

    uint8_t messageBlockByteCount = 0;
    md5_static_assert(UINT8_MAX > (MD5_MESSAGE_BLOCK_SIZE * 2),
                      "messageBlockByteCount cannot fit within a uint8_t");

    while (*messagePtr != 0x00)
    {
        md5_assert(messageBlockByteCount < MD5_MESSAGE_BLOCK_SIZE);

        messagePtr++;
        messageBlockByteCount++;
        context.MessageLengthBits += 8;

        if(messageBlockByteCount == MD5_MESSAGE_BLOCK_SIZE)
        {
            MD5_UpdateHash(&context, (uint8_t *)(messagePtr - messageBlockByteCount), messageBlockByteCount);
            messageBlockByteCount = 0;
        }
    }

    // Allocate memory to store the message remainder + padding + encoded message length
    // We use a buffer length of 1024 bits to cover the worst case scenario,
    // where the length of the message remainder is between 477 and 512 bits.
    uint8_t buffer[MD5_MESSAGE_BLOCK_SIZE * 2];
    uint8_t *bufferPtr = buffer;
    uint8_t bufferSizeBytes = MD5_MESSAGE_BLOCK_SIZE * 2;
    md5_static_assert(UINT8_MAX > (MD5_MESSAGE_BLOCK_SIZE * 2),
                      "bufferSizeBytes cannot fit within a uint8_t");

#if HASHUTIL_SLOW
    // Note (Aaron): Packing the buffer's bits with 1s for debug purposes
    MD5_MemorySet(bufferPtr, 0xff, sizeof(buffer));
#endif

    md5_assert(messageBlockByteCount <= (bufferSizeBytes - MD5_MESSAGE_LENGTH_BLOCK_SHA256 - 1));

    // Copy message remainder (if any) into the buffer
    if (messageBlockByteCount > 0)
    {
        MD5_MemoryCopy(bufferPtr, (uint8_t *)(messagePtr - messageBlockByteCount), messageBlockByteCount);
    }

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + messageBlockByteCount;
    *paddingPtr++ = (1 << 7);

    bool useFullBuffer = (messageBlockByteCount >= (MD5_MESSAGE_BLOCK_SIZE - MD5_MESSAGE_LENGTH_BLOCK_SHA256 - 1));

    // Apply padded 0s
    uint8_t *paddingEndPtr = useFullBuffer
        ? bufferPtr + bufferSizeBytes - MD5_MESSAGE_LENGTH_BLOCK_SHA256
        : bufferPtr + MD5_MESSAGE_BLOCK_SIZE - MD5_MESSAGE_LENGTH_BLOCK_SHA256;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr++ = 0;
    }

    // Append the length of the message as a 64-bit representation
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    *sizePtr = (uint64_t)context.MessageLengthBits;

    // Perform final hash update
    messageBlockByteCount = useFullBuffer ? bufferSizeBytes : MD5_MESSAGE_BLOCK_SIZE;
    md5_assert(messageBlockByteCount == (paddingPtr - bufferPtr) + sizeof(uint64_t));
    MD5_UpdateHash(&context, bufferPtr, messageBlockByteCount);

    // Zero out message remainder to prevent sensitive information being left in memory
    MD5_MemorySet(bufferPtr, 0, messageBlockByteCount);

    // Calculate hash and return
    MD5_ConstructDigest(&context);

    return context;
}


md5_context MD5_HashFile(const char *fileName)
{
    md5_context result;
    MD5_InitializeContext(&result);

    FILE *file = fopen(fileName, "rb");
    if(!file)
    {
        md5_assert(false);

        result.Error = true;
        sprintf(result.ErrorStr, "Unable to open file");
        sprintf(result.DigestStr, "");
        return result;
    }

    uint8_t buffer[MD5_MESSAGE_BLOCK_SIZE * 2];
    uint8_t *bufferPtr = buffer;
    uint8_t bufferSizeBytes = MD5_MESSAGE_BLOCK_SIZE * 2;
    md5_static_assert(UINT8_MAX > (MD5_MESSAGE_BLOCK_SIZE * 2),
                      "bufferSizeBytes cannot fit within a uint8_t");

#if HASHUTIL_SLOW
    // Note (Aaron): Packing the buffer's bits with 1s for debug purposes
    MD5_MemorySet((uint8_t *)buffer, 0xff, sizeof(buffer));
#endif

    size_t readElementSize = sizeof(uint8_t);
    size_t readBlockSize = sizeof(uint8_t) * MD5_MESSAGE_BLOCK_SIZE;
    uint64_t blockBytesRead = 0;

    // Note (Aaron): Sanity check
    md5_assert(readElementSize == 1);

    // Update hash using file contents until we run out of chunks of sufficient size
    blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
    while(blockBytesRead)
    {
        md5_assert(blockBytesRead <= MD5_MESSAGE_BLOCK_SIZE);
        result.MessageLengthBits += ((uint32_t)blockBytesRead * 8);

        if (blockBytesRead == MD5_MESSAGE_BLOCK_SIZE)
        {
            MD5_UpdateHash(&result, bufferPtr, blockBytesRead);
            blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
            continue;
        }

        // Note (Aaron): If we ever read less bytes than MD5_MESSAGE_BLOCK_SIZE, it is time to stop
        // reading the file.
        break;
    }

    if(ferror(file))
    {
        fclose(file);
        md5_assert(false);

        result.Error = true;
        sprintf(result.ErrorStr, "Error reading file");
        sprintf(result.DigestStr, "");
        return result;
    }

    fclose(file);

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + blockBytesRead;
    *paddingPtr++ = (1 << 7);

    bool useFullBuffer = (blockBytesRead >= (MD5_MESSAGE_BLOCK_SIZE - MD5_MESSAGE_LENGTH_BLOCK_SHA256 - 1));

    // Apply padded 0s
    uint8_t *paddingEndPtr = useFullBuffer
        ? bufferPtr + bufferSizeBytes - MD5_MESSAGE_LENGTH_BLOCK_SHA256
        : bufferPtr + MD5_MESSAGE_BLOCK_SIZE - MD5_MESSAGE_LENGTH_BLOCK_SHA256;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr++ = 0;
    }

    // Append the length of the message as a 64-bit representation
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    *sizePtr = (uint64_t)result.MessageLengthBits;

    // Perform final hash update
    blockBytesRead = useFullBuffer ? bufferSizeBytes : MD5_MESSAGE_BLOCK_SIZE;
    md5_assert(blockBytesRead == (paddingPtr - bufferPtr) + sizeof(uint64_t));
    MD5_UpdateHash(&result, bufferPtr, blockBytesRead);

    // Zero out buffer to sanitize potentially sensitive information
    MD5_MemorySet(bufferPtr, 0, blockBytesRead);

    // Calculate hash and return
    MD5_ConstructDigest(&result);

    return result;
}

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_MD5_IMPLEMENTATION
/*
This software is a derived work of the RSA Data Security, Inc. MD5 Message-Digest Algorithm.


------------------------------------------------------------------------------
This software is available under 2 licenses -- choose whichever you prefer.
------------------------------------------------------------------------------
ALTERNATIVE A - MIT License
Copyright (c) 2023 Aaron Hnyduik
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
------------------------------------------------------------------------------
ALTERNATIVE B - Public Domain (www.unlicense.org)
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.
In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
------------------------------------------------------------------------------
*/
