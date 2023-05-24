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
#include <string.h>
#include <assert.h>
#endif

#if HASHUTIL_SLOW
#define sha1_static_assert(expression, string) static_assert(expression, string)
#define sha1_assert(expression) assert(expression)
#else
#define sha1_static_assert(expression, string)
#define sha1_assert(expression)
#endif

#define SHA1_BLOCK_SIZE_BYTES 64        // 512 bits
#define SHA1_BUFFER_SIZE_BYTES 128      // 1024 bits


#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA1_GetVersion()
{
    uint32_t result = HASHUTIL_SHA1_VERSION;
    return result;
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
    memset(context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}


static void SHA1_MemoryCopy(const uint8_t *source, uint8_t *destination, size_t count)
{
    for (int i = 0; i < count; ++i)
    {
        *(destination + i) = *(source + i);
    }
}


// 32-bit Circular bit shift left
static uint32_t SHA1_ROTL(uint32_t value, uint8_t count)
{
    return (value << count) | (value >> (32 - count));
}



static void SHA1_UpdateHash(sha1_context *context, uint8_t *messagePtr, uint64_t byteCount)
{
    // Assert that the message is divisible by 512-bits (64 bytes)
    sha1_assert(byteCount % 64 == 0);

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
    memset(W, 0, sizeof(W));
#endif

    uint32_t temp = 0;

    // 'i' holds the position (offset from ptr) of the current 512 bit block of the message being processed
    for (uint64_t i = 0; i < byteCount; i+=64)
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
        for (int t = 16; t < 80; ++t)
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
    sha1_context result;
    SHA1_InitializeContext(&result);
    uint64_t byteCount = 0;

    while(*messagePtr != 0x00)
    {
        sha1_assert(byteCount <= SHA1_BLOCK_SIZE_BYTES);

        messagePtr++;
        byteCount++;
        result.MessageLengthBits += 8;

        // Process the message in blocks of 512 bits (64 bytes or sixteen 32-bit words)
        if (byteCount == SHA1_BLOCK_SIZE_BYTES)
        {
            SHA1_UpdateHash(&result, (uint8_t *)(messagePtr - byteCount), byteCount);
            byteCount = 0;
        }
    }

    // Allocate a buffer to store the message remainder + padding + message length
    // Note (Aaron): We use a buffer length of 1024 bits to cover the worst case
    // scenario where extra padding is required (where the message remainder is
    // between 447 bits and 512 bits).
    uint8_t buffer[SHA1_BUFFER_SIZE_BYTES];   // 1024 bits
    uint8_t *bufferPtr = buffer;

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    memset(bufferPtr, 0xff, SHA1_BUFFER_SIZE_BYTES);
#endif

    // Apply the final hash update with padding
    // 8 bytes are reserved to store the message length as a 64-bit integer and 1 byte
    // holds the mandatory padding
    bool useExtendedBuffer = (byteCount > (SHA1_BLOCK_SIZE_BYTES - 8 - 1));

    // Assert message remainder is small enough to fit into the buffer along with
    // padding and message length.
    sha1_assert(byteCount < ((useExtendedBuffer ? SHA1_BUFFER_SIZE_BYTES : SHA1_BLOCK_SIZE_BYTES) - 8 - 1));

    // Copy message remainder into buffer
    SHA1_MemoryCopy((uint8_t *)(messagePtr - byteCount), bufferPtr, byteCount);

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + byteCount;
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply padded 0s
    // The last 8 bytes are reserved to store the message length as a 64-bit integer
    uint8_t *paddingEndPtr = useExtendedBuffer
        ? bufferPtr + SHA1_BUFFER_SIZE_BYTES - 8
        : bufferPtr + SHA1_BLOCK_SIZE_BYTES - 8;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append length of message as a 64-bit number (in big endian)
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    uint64_t messageLength64 = result.MessageLengthBits;

    uint32_t endianTest = 0xdeadbeef;
    bool isLittleEndian = *(unsigned char *)&endianTest;
    if (isLittleEndian)
    {
        // Convert bits to big endian
        messageLength64 =
            ((messageLength64 >> 56) & 0xff)
            | ((messageLength64 >> 40) & 0xff00)
            | ((messageLength64 >> 24) & 0xff0000)
            | ((messageLength64 >> 8) & 0xff000000)
            | ((messageLength64 << 8) & 0xff00000000)
            | ((messageLength64 << 24) & 0xff0000000000)
            | ((messageLength64 << 40) & 0xff000000000000)
            | ((messageLength64 << 56) & 0xff00000000000000);
    }

    *sizePtr = messageLength64;

    // Apply final hash update and construct the digest
    byteCount = useExtendedBuffer ? SHA1_BUFFER_SIZE_BYTES : SHA1_BLOCK_SIZE_BYTES;
    SHA1_UpdateHash(&result, bufferPtr, byteCount);
    SHA1_ConstructDigest(&result);

    return result;
}


sha1_context SHA1_HashFile(const char *fileName)
{
    uint8_t buffer[SHA1_BUFFER_SIZE_BYTES];
    uint8_t *bufferPtr = buffer;

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    memset(bufferPtr, 0xff, SHA1_BUFFER_SIZE_BYTES);
#endif

    size_t bytesRead;
    uint64_t byteCount = 0;

    FILE *file = fopen(fileName, "rb");
    if (!file)
    {
        printf("Unable to open file '%s'", fileName);
        exit(1);
    }

    sha1_context result;
    SHA1_InitializeContext(&result);
    size_t readElementSize = 1;
    size_t readBlockSize = sizeof(uint8_t) * SHA1_BLOCK_SIZE_BYTES;

    // Update hash using file contents until we run out of blocks of sufficient size
    bytesRead = fread(buffer, readElementSize, readBlockSize, file);
    while(bytesRead)
    {
        sha1_assert(bytesRead <= SHA1_BLOCK_SIZE_BYTES);

        result.MessageLengthBits += (bytesRead * 8);
        // Note (Aaron): Hashes are updated using 'byteCount' rather than 'bytesRead' as
        // 'bytesRead' will be 0 after exiting the loop.
        byteCount = (uint64_t)bytesRead;

        if (byteCount == SHA1_BLOCK_SIZE_BYTES)
        {
            SHA1_UpdateHash(&result, bufferPtr, byteCount);
            bytesRead = fread(buffer, readElementSize, readBlockSize, file);
            continue;
        }

        // Note (Aaron): If we ever read less bytes than SHA1_BLOCK_SIZE_BYTES, it is time to stop
        // reading the file.
        bytesRead = 0;
    }

    if (ferror(file))
    {
        printf("Error reading file '%s'", fileName);
        fclose(file);
        exit(1);
    }

    fclose(file);

    // Apply the final hash update with padding
    bool useExtendedBuffer = (byteCount > (SHA1_BLOCK_SIZE_BYTES - 8 - 1));

    // Assert message remainder is small enough to fit into the buffer along with
    // padding and message length.
    sha1_assert(byteCount < (SHA1_BUFFER_SIZE_BYTES - 8 - 1));

    // Apply padded 1
    uint8_t *paddingPtr = bufferPtr + byteCount;
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply padded 0s
    uint8_t *paddingEndPtr = useExtendedBuffer
        ? bufferPtr + (SHA1_BUFFER_SIZE_BYTES - 8)
        : buffer + (SHA1_BLOCK_SIZE_BYTES - 8);

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append length of message as a 64-bit number (in big endian)
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    uint64_t messageLength64 = result.MessageLengthBits;

    uint32_t endianTest = 0xdeadbeef;
    bool isLittleEndian = *(unsigned char *)&endianTest;
    if (isLittleEndian)
    {
        // Convert bits to big endian
        messageLength64 =
            ((messageLength64 >> 56) & 0xff)
            | ((messageLength64 >> 40) & 0xff00)
            | ((messageLength64 >> 24) & 0xff0000)
            | ((messageLength64 >> 8) & 0xff000000)
            | ((messageLength64 << 8) & 0xff00000000)
            | ((messageLength64 << 24) & 0xff0000000000)
            | ((messageLength64 << 40) & 0xff000000000000)
            | ((messageLength64 << 56) & 0xff00000000000000);
    }

    *sizePtr = messageLength64;

    // Apply final hash update and construct the digest
    byteCount = useExtendedBuffer ? SHA1_BUFFER_SIZE_BYTES : SHA1_BLOCK_SIZE_BYTES;
    SHA1_UpdateHash(&result, bufferPtr, byteCount);
    SHA1_ConstructDigest(&result);

    return result;
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
