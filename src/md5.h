/* TODO (Aaron):
    - Add error handling to context so that we don't have to exit() on failure and can eliminate stdlib
    - Update file to conform more with sha2.h
        - Update MemoryCopy()
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

static uint32_t const HASHUTIL_MD5_VERSION = 1;

typedef struct md5_context
{
    uint32_t MessageLengthBits;
    uint32_t State[4];
    uint8_t Digest[16];
    char DigestStr[33];
} md5_context;


#ifdef __cplusplus
extern "C" {
#endif

uint32_t MD5GetVersion();
md5_context MD5HashString(char *messagePtr);
md5_context MD5HashFile(const char *fileName);

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_MD5_H
// end of header file ////////////////////////////////////////////////////////


#ifdef HASHUTIL_MD5_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#if HASHUTIL_SLOW
#include <string.h>
#endif

#if HASHUTIL_SLOW
#define MD5Assert(Expression) if (!(Expression)) {*(int *)0 = 0;}
#else
#define MD5Assert(Expression)
#endif

#define MD5ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

#define MD5_BUFFER_BYTE_SIZE 128
#define MD5_CHUNK_BYTE_COUNT 64


#ifdef __cplusplus
extern "C" {
#endif

uint32_t MD5GetVersion()
{
    uint32_t result = HASHUTIL_MD5_VERSION;
    return result;
}

static void MD5InitializeContext(md5_context *context)
{
    context->MessageLengthBits = 0;
    context->State[0] = 0x67452301;
    context->State[1] = 0xefcdab89;
    context->State[2] = 0x98badcfe;
    context->State[3] = 0x10325476;
#if HASHUTIL_SLOW
    memset(context->Digest, 0, sizeof(context->Digest));
    memset(context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}

static void MD5MemoryCopy(const uint8_t *source, uint8_t *destination, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(destination + i) = *(source + i);
    }
}


static void MD5MemoryZero(uint8_t *ptr, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(ptr + i) = 0;
    }
}


static uint32_t MD5CircularBitShiftLeft(uint32_t value, uint8_t count)
{
    return (value << count) | (value >> (32-count));
}


// #define MD5AuxF(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
static uint32_t MD5AuxF(uint32_t x, uint32_t y, uint32_t z)
{
    // Function F(X,Y,Z) = XY v not(X) Z
    uint32_t result = (x & y) | (~x & z);
    return result;
}


// #define MD5AuxG(X, Y, Z) (((X) & (Z)) | ((Y) & (~Z)))
static uint32_t MD5AuxG(uint32_t x, uint32_t y, uint32_t z)
{
    // Function G(X,Y,Z) = XZ v Y not(Z)
    uint32_t result = (x & z) | (y & ~z);
    return result;
}


// #define MD5AuxH(X, Y, Z) ((X) ^ (Y) ^ (Z))
static uint32_t MD5AuxH(uint32_t x, uint32_t y, uint32_t z)
{
    // Function H(X,Y,Z) = X xor Y xor Z
    uint32_t result = (x ^ y ^ z);
    return result;
}


// #define MD5AuxI(X, Y, Z) ((Y) ^ ((X) | (~Z)))
static uint32_t MD5AuxI(uint32_t x, uint32_t y, uint32_t z)
{
    // Function I(X,Y,Z) = Y xor (X v not(Z))
    uint32_t result = y ^ (x | ~z);
    return result;
}


static uint32_t MD5TransformFF(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5AuxF(B, C, D) + X + T;
    result = MD5CircularBitShiftLeft(result, S);
    return B + result;
}


static uint32_t MD5TransformGG(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5AuxG(B, C, D) + X + T;
    result = MD5CircularBitShiftLeft(result, S);
    return B + result;
}


static uint32_t MD5TransformHH(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5AuxH(B, C, D) + X + T;
    result = MD5CircularBitShiftLeft(result, S);
    return B + result;
}


static uint32_t MD5TransformII(uint32_t A, uint32_t B, uint32_t C, uint32_t D, uint32_t X, uint8_t S, uint32_t T)
{
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
    uint32_t result = A + MD5AuxI(B, C, D) + X + T;
    result = MD5CircularBitShiftLeft(result, S);
    return B + result;
}


static void MD5UpdateHash(md5_context *context, uint8_t *ptr, uint32_t byteCount)
{
    // Assert that the block length is divisible by 512 bits (64 bytes)
    MD5Assert(byteCount % 64 == 0);

    // Create 512-bit block
    uint32_t block[16];
#if HASHUTIL_SLOW
    memset(block, 0, sizeof(block));
#endif

    // Note (Aaron): Iterate over 512-bit (64 byte) blocks of the message.
    // 'i' represents the byte position in the message.
    for (uint32_t i = 0;
         i < (byteCount);
         i+=64)
    {
        for (int j = 0; j < 16; ++j)
        {
            // Note (Aaron): This will work regardless of endianness
            block[j] = (uint32_t)(*(ptr + i + (j * 4)))
                | (uint32_t)(*(ptr + i + (j * 4) + 1) << 8)
                | (uint32_t)(*(ptr + i + (j * 4) + 2) << 16)
                | (uint32_t)(*(ptr + i + (j * 4) + 3) << 24);

            // Note (Aaron): This will only work on little-endian systems (with no alignment restrictions)
            // uint32_t endianness = 0xdeadbeef;
            // MD5Assert((*(unsigned char *)&endianness) == 0xef)
            // block[j] = *(uint32_t *)((context->MessagePtr + i + (j * 4)));
        }

        uint32_t A = context->State[0];
        uint32_t B = context->State[1];
        uint32_t C = context->State[2];
        uint32_t D = context->State[3];

        // Perform MD5 transformations
        // Round 1
        A = MD5TransformFF(A, B, C, D, block[0], 7, 0xd76aa478);
        D = MD5TransformFF(D, A, B, C, block[1], 12, 0xe8c7b756);
        C = MD5TransformFF(C, D, A, B, block[2], 17, 0x242070db);
        B = MD5TransformFF(B, C, D, A, block[3], 22, 0xc1bdceee);

        A = MD5TransformFF(A, B, C, D, block[4], 7, 0xf57c0faf);
        D = MD5TransformFF(D, A, B, C, block[5], 12, 0x4787c62a);
        C = MD5TransformFF(C, D, A, B, block[6], 17, 0xa8304613);
        B = MD5TransformFF(B, C, D, A, block[7], 22, 0xfd469501);

        A = MD5TransformFF(A, B, C, D, block[8], 7, 0x698098d8);
        D = MD5TransformFF(D, A, B, C, block[9], 12, 0x8b44f7af);
        C = MD5TransformFF(C, D, A, B, block[10], 17, 0xffff5bb1);
        B = MD5TransformFF(B, C, D, A, block[11], 22, 0x895cd7be);

        A = MD5TransformFF(A, B, C, D, block[12], 7, 0x6b901122);
        D = MD5TransformFF(D, A, B, C, block[13], 12, 0xfd987193);
        C = MD5TransformFF(C, D, A, B, block[14], 17, 0xa679438e);
        B = MD5TransformFF(B, C, D, A, block[15], 22, 0x49b40821);

        // Round 2
        A = MD5TransformGG(A, B, C, D, block[1], 5, 0xf61e2562);
        D = MD5TransformGG(D, A, B, C, block[6], 9, 0xc040b340);
        C = MD5TransformGG(C, D, A, B, block[11], 14, 0x265e5a51);
        B = MD5TransformGG(B, C, D, A, block[0], 20, 0xe9b6c7aa);

        A = MD5TransformGG(A, B, C, D, block[5], 5, 0xd62f105d);
        D = MD5TransformGG(D, A, B, C, block[10],9, 0x2441453);
        C = MD5TransformGG(C, D, A, B, block[15], 14, 0xd8a1e681);
        B = MD5TransformGG(B, C, D, A, block[4], 20, 0xe7d3fbc8);

        A = MD5TransformGG(A, B, C, D, block[9], 5, 0x21e1cde6);
        D = MD5TransformGG(D, A, B, C, block[14],9, 0xc33707d6);
        C = MD5TransformGG(C, D, A, B, block[3], 14, 0xf4d50d87);
        B = MD5TransformGG(B, C, D, A, block[8], 20, 0x455a14ed);

        A = MD5TransformGG(A, B, C, D, block[13], 5, 0xa9e3e905);
        D = MD5TransformGG(D, A, B, C, block[2], 9, 0xfcefa3f8);
        C = MD5TransformGG(C, D, A, B, block[7], 14, 0x676f02d9);
        B = MD5TransformGG(B, C, D, A, block[12], 20, 0x8d2a4c8a);

        // Round 3
        A = MD5TransformHH(A, B, C, D, block[5], 4, 0xfffa3942);
        D = MD5TransformHH(D, A, B, C, block[8], 11, 0x8771f681);
        C = MD5TransformHH(C, D, A, B, block[11], 16, 0x6d9d6122);
        B = MD5TransformHH(B, C, D, A, block[14], 23, 0xfde5380c);

        A = MD5TransformHH(A, B, C, D, block[1], 4, 0xa4beea44);
        D = MD5TransformHH(D, A, B, C, block[4], 11, 0x4bdecfa9);
        C = MD5TransformHH(C, D, A, B, block[7], 16, 0xf6bb4b60);
        B = MD5TransformHH(B, C, D, A, block[10], 23, 0xbebfbc70);

        A = MD5TransformHH(A, B, C, D, block[13], 4, 0x289b7ec6);
        D = MD5TransformHH(D, A, B, C, block[0], 11, 0xeaa127fa);
        C = MD5TransformHH(C, D, A, B, block[3], 16, 0xd4ef3085);
        B = MD5TransformHH(B, C, D, A, block[6], 23, 0x4881d05);

        A = MD5TransformHH(A, B, C, D, block[9], 4, 0xd9d4d039);
        D = MD5TransformHH(D, A, B, C, block[12], 11, 0xe6db99e5);
        C = MD5TransformHH(C, D, A, B, block[15], 16, 0x1fa27cf8);
        B = MD5TransformHH(B, C, D, A, block[2], 23, 0xc4ac5665);

        // Round 4
        A = MD5TransformII(A, B, C, D, block[0], 6, 0xf4292244);
        D = MD5TransformII(D, A, B, C, block[7], 10, 0x432aff97);
        C = MD5TransformII(C, D, A, B, block[14], 15, 0xab9423a7);
        B = MD5TransformII(B, C, D, A, block[5], 21, 0xfc93a039);

        A = MD5TransformII(A, B, C, D, block[12], 6, 0x655b59c3);
        D = MD5TransformII(D, A, B, C, block[3], 10, 0x8f0ccc92);
        C = MD5TransformII(C, D, A, B, block[10], 15, 0xffeff47d);
        B = MD5TransformII(B, C, D, A, block[1], 21, 0x85845dd1);

        A = MD5TransformII(A, B, C, D, block[8], 6, 0x6fa87e4f);
        D = MD5TransformII(D, A, B, C, block[15], 10, 0xfe2ce6e0);
        C = MD5TransformII(C, D, A, B, block[6], 15, 0xa3014314);
        B = MD5TransformII(B, C, D, A, block[13], 21, 0x4e0811a1);

        A = MD5TransformII(A, B, C, D, block[4], 6, 0xf7537e82);
        D = MD5TransformII(D, A, B, C, block[11], 10, 0xbd3af235);
        C = MD5TransformII(C, D, A, B, block[2], 15, 0x2ad7d2bb);
        B = MD5TransformII(B, C, D, A, block[9], 21, 0xeb86d391);

        context->State[0] += A;
        context->State[1] += B;
        context->State[2] += C;
        context->State[3] += D;
    }

    // Zero out block[] to prevent sensitive information being left in memory
    MD5MemoryZero((uint8_t *)&block, MD5ArrayCount(block));
}


static void MD5ConstructDigest(md5_context *context)
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


md5_context MD5HashString(char *messagePtr)
{
    md5_context result;
    MD5InitializeContext(&result);

    uint32_t byteCount = 0;

    while (*messagePtr != 0x00)
    {
        messagePtr++;
        result.MessageLengthBits += 8;
        byteCount++;

        if(byteCount == MD5_CHUNK_BYTE_COUNT)
        {
            MD5UpdateHash(&result, (uint8_t *)(messagePtr - byteCount), byteCount);
            byteCount = 0;
        }
    }

    // Allocate memory to store the message remainder + padding + encoded message length
    // We use a buffer length of 1024 bits to cover the worst case scenario,
    // where the length of the message remainder is between 477 and 512 bits.
    uint8_t buffer[MD5_BUFFER_BYTE_SIZE];
#if HASHUTIL_SLOW
    memset(buffer, 0, sizeof(buffer));
#endif
    uint8_t *bufferPtr = buffer;
    bool useExtendedMargine = (byteCount >= (MD5_CHUNK_BYTE_COUNT - 8));

    // Copy message remainder into the buffer
    MD5Assert(byteCount < MD5_BUFFER_BYTE_SIZE);
    MD5MemoryCopy((uint8_t *)(messagePtr - byteCount), bufferPtr, byteCount);

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + byteCount;
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply padded 0s
    uint8_t *paddingEndPtr = useExtendedMargine
        ? bufferPtr + MD5_BUFFER_BYTE_SIZE - 8
        : bufferPtr + MD5_CHUNK_BYTE_COUNT - 8;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append the length of the message as a 64-bit representation
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    *sizePtr = (uint64_t)result.MessageLengthBits;

    // Perform final hash update
    byteCount = useExtendedMargine ? MD5_BUFFER_BYTE_SIZE : MD5_CHUNK_BYTE_COUNT;
    MD5Assert(byteCount == (paddingPtr - bufferPtr) + sizeof(uint64_t));
    MD5UpdateHash(&result, bufferPtr, byteCount);

    // Zero out message remainder to prevent sensitive information being left in memory
    MD5MemoryZero(bufferPtr, byteCount);

    // Calculate hash and return
    MD5ConstructDigest(&result);

    return result;
}


md5_context MD5HashFile(const char *fileName)
{
    // Note (Aaron): Read the file in 64 byte chunks but allocate 128 bytes in case
    // we need an extended margine when padding the end of the file. 64 byte chunks are
    // used as this is the size of blocks MD5 processes at one time.
    uint8_t buffer[MD5_BUFFER_BYTE_SIZE];
#if HASHUTIL_SLOW
    memset(buffer, 0, sizeof(buffer));
#endif
    size_t bytesRead;
    uint32_t byteCount = 0;

    FILE *file = fopen(fileName, "rb");
    if(!file)
    {
        printf("Unable to open file '%s'", fileName);
        exit(1);
    }

    md5_context result;
    MD5InitializeContext(&result);
    uint8_t *bufferPtr = buffer;
    size_t readElementSize = 1;
    size_t readBlockSize = sizeof(uint8_t) * MD5_CHUNK_BYTE_COUNT;

    // Update hash using file contents until we run out of chunks of sufficient size
    bytesRead = fread(buffer, readElementSize, readBlockSize, file);
    while(bytesRead)
    {
        MD5Assert(bytesRead <= MD5_CHUNK_BYTE_COUNT);
        result.MessageLengthBits += ((uint32_t)bytesRead * 8);
        // Note (Aaron): Hashes are updated using 'byteCount' rather than 'bytesRead' as
        // 'bytesRead' will be 0 after exiting the loop.
        byteCount = (uint32_t)bytesRead;

        if (byteCount == MD5_CHUNK_BYTE_COUNT)
        {
            MD5UpdateHash(&result, bufferPtr, byteCount);
            bytesRead = fread(buffer, readElementSize, readBlockSize, file);
            continue;
        }

        // Note (Aaron): If we ever read less bytes than MD5_CHUNK_BYTE_COUNT, it is time to stop
        // reading the file.
        bytesRead = 0;
    }

    if(ferror(file))
    {
        printf("Error reading file '%s'", fileName);
        fclose(file);
        exit(1);
    }

    fclose(file);

    // Apply the final hash update with padding
    bool useExtendedMargine = (byteCount >= (MD5_CHUNK_BYTE_COUNT - 8));

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + byteCount;
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply padded 0s
    uint8_t *paddingEndPtr = useExtendedMargine
        ? bufferPtr + MD5_BUFFER_BYTE_SIZE - 8
        : bufferPtr + MD5_CHUNK_BYTE_COUNT - 8;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append the length of the message as a 64-bit representation
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    *sizePtr = (uint64_t)result.MessageLengthBits;

    // Perform final hash update
    byteCount = useExtendedMargine ? MD5_BUFFER_BYTE_SIZE : MD5_CHUNK_BYTE_COUNT;
    MD5Assert(byteCount == (paddingPtr - bufferPtr) + sizeof(uint64_t));
    MD5UpdateHash(&result, bufferPtr, byteCount);

    // Zero out buffer to prevent santize potentially sensitive information
    MD5MemoryZero(bufferPtr, byteCount);

    // Calculate hash and return
    MD5ConstructDigest(&result);

    return result;
}

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_MD5_IMPLEMENTATION
