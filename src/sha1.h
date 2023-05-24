/* TODO (Aaron):
    - Add readme / documentation to header
    - Update file to conform more with sha2.h
        - Guard against messages over 2^64-1 bits in length
        - Add error handling to context so that we don't have to exit() on failure and can eliminate stdlib
*/

/*  sha1.h - Implements the SHA1 hashing algorithms.

    Do this:
      #define HASHUTIL_SHA1_IMPLEMENTATION
   before you include this file in *one* C or C++ file to create the implementation.
*/

#ifndef HASHUTIL_SHA1_H
#define HASHUTIL_SHA1_H

#include <stdint.h>

static uint32_t const HASHUTIL_SHA1_VERSION = 1;

typedef struct sha1_context
{
    uint64_t MessageLengthBits;
    union
    {
        uint32_t H[5];
        struct
        {
            uint32_t H0;
            uint32_t H1;
            uint32_t H2;
            uint32_t H3;
            uint32_t H4;
        };
    };

    char DigestStr[41];
} sha1_context;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA1_GetVersion();
sha1_context SHA1_HashString(char *messagePtr);
sha1_context SHA1_HashFile(const char *fileName);

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA1_H
// end of header file ////////////////////////////////////////////////////////


#ifdef HASHUTIL_SHA1_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#if HASHUTIL_SLOW
#include <assert.h>
#endif

#if HASHUTIL_SLOW
#define sha1_static_assert(expression, string) static_assert(expression, string)
#define sha1_assert(expression) assert(expression)
#else
#define sha1_static_assert(expression, string)
#define sha1_assert(expression)
#endif

#define SHA1_ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

#define SHA1_MESSAGE_BLOCK_SIZE 64   // 512 bits
#define SHA1_MESSAGE_LENGTH_BLOCK_SIZE 8


#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA1_GetVersion()
{
    uint32_t result = HASHUTIL_SHA1_VERSION;
    return result;
}


static void *SHA1_MemoryCopy(void *destPtr, void const *sourcePtr, size_t size)
{
    sha1_assert(size > 0);

    unsigned char *source = (unsigned char *)sourcePtr;
    unsigned char *dest = (unsigned char *)destPtr;
    while(size--) *dest++ = *source++;

    return destPtr;
}


static void *SHA1_MemorySet(uint8_t *destPtr, int c, size_t count)
{
    sha1_assert(count > 0);

    unsigned char *dest = (unsigned char *)destPtr;
    while(count--) *dest++ = (unsigned char)c;

    return destPtr;
}


static void SHA1_InitializeContext(sha1_context *context)
{
    context->MessageLengthBits = 0;
    context->H0 = 0x67452301;
    context->H1 = 0xefcdab89;
    context->H2 = 0x98badcfe;
    context->H3 = 0x10325476;
    context->H4 = 0xc3d2e1f0;
#if HASHUTIL_SLOW
    SHA1_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}


// 32-bit Circular bit shift left
static uint32_t SHA1_ROTL(uint32_t value, uint8_t count)
{
    return (value << count) | (value >> (32 - count));
}


static bool SHA1_IsSystemLittleEndian()
{
    uint32_t endianTest = 0xdeadbeef;
    bool isLittleEndian = *(unsigned char *)&endianTest = 0xef;

    return isLittleEndian;
}


static void SHA1_MirrorBits64(uint64_t *bits)
{
    *bits = ((*bits >> 56) & 0xff)
         | ((*bits >> 40) & 0xff00)
         | ((*bits >> 24) & 0xff0000)
         | ((*bits >> 8) & 0xff000000)
         | ((*bits << 8) & 0xff00000000)
         | ((*bits << 24) & 0xff0000000000)
         | ((*bits << 40) & 0xff000000000000)
         | ((*bits << 56) & 0xff00000000000000);
}


static void SHA1_UpdateHash(sha1_context *context, uint8_t *messagePtr, uint64_t byteCount)
{
    sha1_assert(byteCount % SHA1_MESSAGE_BLOCK_SIZE == 0);

    uint32_t A, B, C, D, E;
#if HASHUTIL_SLOW
    A = 0;
    B = 0;
    C = 0;
    D = 0;
    E = 0;
#endif

    uint32_t W[80];
#if HASHUTIL_SLOW
    SHA1_MemorySet((uint8_t *)W, 0, sizeof(W));
#endif

    uint32_t temp = 0;

    // 'i' holds the position (offset from ptr) of the current 512 bit block of the message being processed
    for (uint64_t i = 0; i < byteCount; i+=SHA1_MESSAGE_BLOCK_SIZE)
    {
        // 'j' holds the word position from the start of the current block of 512 bits being processed
        // 16 words == 64 bytes == 512 bits
        for (int j = 0; j < 16; ++j)
        {
            W[j] = (uint32_t)(*(messagePtr + i + (j * 4)) << 24)
                | (uint32_t)(*(messagePtr + i + (j * 4) + 1) << 16)
                | (uint32_t)(*(messagePtr + i + (j * 4) + 2) << 8)
                | (uint32_t)(*(messagePtr + i + (j * 4) + 3));
        }

        // b. For t = 16 to 79 let
        for (int t = 16; t < SHA1_ArrayCount(W); ++t)
        {
            //  W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16))
            W[t] = SHA1_ROTL(
                (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]),
                1);
        }

        // c. Let A = H0, B = H1, C = H2, D = H3, E = H4
        A = context->H0;
        B = context->H1;
        C = context->H2;
        D = context->H3;
        E = context->H4;

        // d. For t = 0 to 79 do
        //   TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
        //   E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        for (int t = 0; t < 20; ++t)
        {
            // f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)
            // K(t) = 5A827999         ( 0 <= t <= 19)
            temp = SHA1_ROTL(A, 5);
            temp += ((B & C) | ((~B) & D))
                + E
                + W[t]
                + 0x5a827999;
            E = D;
            D = C;
            C = SHA1_ROTL(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 20; t < 40; ++t)
        {
            // f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)
            // K(t) = 6ED9EBA1         (20 <= t <= 39)
            temp = SHA1_ROTL(A, 5);
            temp += (B ^ C ^ D)
                + E
                + W[t]
                + 0x6ed9eba1;
            E = D;
            D = C;
            C = SHA1_ROTL(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 40; t < 60; ++t)
        {
            // f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
            // K(t) = 8F1BBCDC         (40 <= t <= 59)
            temp = SHA1_ROTL(A, 5);
            temp += ((B & C) | (B & D) | (C & D))
                + E
                + W[t]
                + 0x8f1bbcdc;

            E = D;
            D = C;
            C = SHA1_ROTL(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 60; t < 80; ++t)
        {
            temp = SHA1_ROTL(A, 5);
            // f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79)
            // K(t) = CA62C1D6         (60 <= t <= 79).
            temp += (B ^ C ^ D)
                + E
                + W[t]
                + 0xca62c1d6;

            E = D;
            D = C;
            C = SHA1_ROTL(B, 30);
            B = A;
            A = temp;
        }

        // e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4
        //  + E.
        context->H0 += A;
        context->H1 += B;
        context->H2 += C;
        context->H3 += D;
        context->H4 += E;
    }
}


static void SHA1_ConstructDigest(sha1_context *context)
{
    sprintf(context->DigestStr,
            "%08x%08x%08x%08x%08x",
            context->H0,
            context->H1,
            context->H2,
            context->H3,
            context->H4);
}


sha1_context SHA1_HashString(char *messagePtr)
{
    sha1_context context;
    SHA1_InitializeContext(&context);

    uint8_t messageBlockByteCount = 0;
    sha1_static_assert(UINT8_MAX > (SHA1_MESSAGE_BLOCK_SIZE * 2),
                       "messageBlockByteCount cannot fit within a uint8_t");

    while(*messagePtr != 0x00)
    {
        sha1_assert(messageBlockByteCount <= SHA1_MESSAGE_BLOCK_SIZE);

        messagePtr++;
        messageBlockByteCount++;
        context.MessageLengthBits += 8;

        // Process the message in blocks of 512 bits (64 bytes or sixteen 32-bit words)
        if (messageBlockByteCount == SHA1_MESSAGE_BLOCK_SIZE)
        {
            SHA1_UpdateHash(&context, (uint8_t *)(messagePtr - messageBlockByteCount), messageBlockByteCount);
            messageBlockByteCount = 0;
        }
    }

    // Allocate a buffer to store the message remainder + padding + message length
    // Note (Aaron): We use a buffer length of 1024 bits to cover the worst case
    // scenario where extra padding is required (where the message remainder is
    // between 447 bits and 512 bits).
    uint8_t buffer[SHA1_MESSAGE_BLOCK_SIZE * 2];
    uint8_t *bufferPtr = buffer;
    uint8_t bufferSizeBytes = SHA1_MESSAGE_BLOCK_SIZE * 2;
    sha1_static_assert(UINT8_MAX > (SHA1_MESSAGE_BLOCK_SIZE * 2),
                       "bufferSizeBytes cannot fit within a uint8_t");

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    SHA1_MemorySet(bufferPtr, 0xff, sizeof(buffer));
#endif

    // Apply the final hash update with padding
    // 8 bytes are reserved to store the message length as a 64-bit integer and 1 byte
    // holds the mandatory padding
    sha1_assert(messageBlockByteCount <= (bufferSizeBytes - SHA1_MESSAGE_LENGTH_BLOCK_SIZE - 1));

    // Copy message remainder into buffer
    if (messageBlockByteCount > 0)
    {
        SHA1_MemoryCopy(bufferPtr, (uint8_t *)(messagePtr - messageBlockByteCount), messageBlockByteCount);
    }

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + messageBlockByteCount;
    *paddingPtr++ = (1 << 7);

    bool useFullBuffer = (messageBlockByteCount > (SHA1_MESSAGE_BLOCK_SIZE - SHA1_MESSAGE_LENGTH_BLOCK_SIZE - 1));

    // Apply padded 0s
    // The last 8 bytes are reserved to store the message length as a 64-bit integer
    uint8_t *paddingEndPtr = useFullBuffer
        ? bufferPtr + bufferSizeBytes - SHA1_MESSAGE_LENGTH_BLOCK_SIZE
        : bufferPtr + SHA1_MESSAGE_BLOCK_SIZE - SHA1_MESSAGE_LENGTH_BLOCK_SIZE;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr++ = 0;
    }

    // Append length of message as a 64-bit number (in big endian)
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    uint64_t messageLength64 = context.MessageLengthBits;

    if (SHA1_IsSystemLittleEndian())
    {
        // Convert bits to big endian
        SHA1_MirrorBits64(&messageLength64);
    }

    *sizePtr = messageLength64;

    // Apply final hash update and construct the digest
    messageBlockByteCount = useFullBuffer ? bufferSizeBytes : SHA1_MESSAGE_BLOCK_SIZE;
    SHA1_UpdateHash(&context, bufferPtr, messageBlockByteCount);
    SHA1_ConstructDigest(&context);

    return context;
}


sha1_context SHA1_HashFile(const char *fileName)
{
    sha1_context context;
    SHA1_InitializeContext(&context);

    FILE *file = fopen(fileName, "rb");
    if (!file)
    {
        printf("Unable to open file '%s'", fileName);
        exit(1);
    }

    uint8_t buffer[SHA1_MESSAGE_BLOCK_SIZE * 2];
    uint8_t *bufferPtr = buffer;
    uint8_t bufferSizeBytes = SHA1_MESSAGE_BLOCK_SIZE * 2;
    sha1_static_assert(UINT8_MAX > (SHA1_MESSAGE_BLOCK_SIZE * 2),
                       "bufferSizeBytes cannot fit within a uint8_t");

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    SHA1_MemorySet(bufferPtr, 0xff, bufferSizeBytes);
#endif

    size_t blockBytesRead;
    size_t readElementSize = sizeof(uint8_t);
    size_t readBlockSize = sizeof(uint8_t) * SHA1_MESSAGE_BLOCK_SIZE;

    // Note (Aaron): Sanity check
    sha1_assert(readElementSize == 1);

    // Update hash using file contents until we run out of blocks of sufficient size
    blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
    while(blockBytesRead)
    {
        sha1_assert(blockBytesRead <= SHA1_MESSAGE_BLOCK_SIZE);


        context.MessageLengthBits += (blockBytesRead * 8);
        if (blockBytesRead == SHA1_MESSAGE_BLOCK_SIZE)
        {
            SHA1_UpdateHash(&context, bufferPtr, blockBytesRead);
            blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
            continue;
        }

        // Note (Aaron): If we ever read less bytes than SHA1_MESSAGE_BLOCK_SIZE, it is time to stop
        // reading the file.
        break;
    }

    if (ferror(file))
    {
        printf("Error reading file '%s'", fileName);
        fclose(file);
        exit(1);
    }

    fclose(file);

    // Apply the final hash update with padding
    sha1_assert(blockBytesRead < (bufferSizeBytes - SHA1_MESSAGE_LENGTH_BLOCK_SIZE - 1));

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + blockBytesRead;
    *paddingPtr++ = (1 << 7);

    bool useExtendedBuffer = (blockBytesRead > (SHA1_MESSAGE_BLOCK_SIZE - SHA1_MESSAGE_LENGTH_BLOCK_SIZE - 1));

    // Apply padded 0s
    uint8_t *paddingEndPtr = useExtendedBuffer
        ? bufferPtr + (bufferSizeBytes - SHA1_MESSAGE_LENGTH_BLOCK_SIZE)
        : bufferPtr + (SHA1_MESSAGE_BLOCK_SIZE - SHA1_MESSAGE_LENGTH_BLOCK_SIZE);

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr++ = 0;
    }

    // Append length of message as a 64-bit number (in big endian)
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    uint64_t messageLength64 = context.MessageLengthBits;

    if (SHA1_IsSystemLittleEndian())
    {
        // Convert bits to big endian
        SHA1_MirrorBits64(&messageLength64);
    }

    *sizePtr = messageLength64;

    // Apply final hash update and construct the digest
    blockBytesRead = useExtendedBuffer ? bufferSizeBytes : SHA1_MESSAGE_BLOCK_SIZE;
    SHA1_UpdateHash(&context, bufferPtr, blockBytesRead);
    SHA1_ConstructDigest(&context);

    return context;
}

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA1_IMPLEMENTATION
/*
This software is a derived work of RFC 3174 (https://www.rfc-editor.org/rfc/rfc3174).

    Copyright (C) The Internet Society (2001).  All Rights Reserved.

    This document and translations of it may be copied and furnished to
    others, and derivative works that comment on or otherwise explain it
    or assist in its implementation may be prepared, copied, published
    and distributed, in whole or in part, without restriction of any
    kind, provided that the above copyright notice and this paragraph are
    included on all such copies and derivative works.  However, this
    document itself may not be modified in any way, such as by removing
    the copyright notice or references to the Internet Society or other
    Internet organizations, except as needed for the purpose of
    developing Internet standards in which case the procedures for
    copyrights defined in the Internet Standards process must be
    followed, or as required to translate it into languages other than
    English.


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
