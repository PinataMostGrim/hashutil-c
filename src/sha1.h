#if !defined(SHA1_H)
#include <stdio.h>
#include "hashutil.h"

#if HASHUTIL_SLOW
#include <string.h>
#endif

struct sha1_context
{
    uint32 MessageLengthBits = 0;
    union
    {
        uint32 H[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
        struct
        {
            uint32 H0;
            uint32 H1;
            uint32 H2;
            uint32 H3;
            uint32 H4;
        };
    };

    char DigestStr[41];
};

internal uint32
SHA1CircularLeftShift(uint32 value, uint8 shift)
{
    return (value << shift) | (value >> (32-shift));
}

internal void
SHA1UpdateHash(sha1_context *context, uint8 *messagePtr, uint64 byteCount)
{
    // Assert that the message is divisible by 512-bits (64 bytes)
    Assert(byteCount % 64 == 0);

    uint32 A, B, C, D, E = 0;
    uint32 W[80] = {};
    uint32 temp = 0;

    // 'i' holds the position (offset from ptr) of the current 512 bit block of the message being processed
    for (uint64 i = 0;
         i < byteCount;
         i+=64)
    {

        // 'j' holds the word position from the start of the current block of 512 bits being processed
        // 16 words == 64 bytes == 512 bits
        for (int j = 0; j < 16; ++j)
        {
            W[j] = (uint32)(*(messagePtr + i + (j * 4)) << 24)
                | (uint32)(*(messagePtr + i + (j * 4) + 1) << 16)
                | (uint32)(*(messagePtr + i + (j * 4) + 2) << 8)
                | (uint32)(*(messagePtr + i + (j * 4) + 3));
        }

        // b. For t = 16 to 79 let
        for (int t = 16; t < 80; ++t)
        {
            //  W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16))
            W[t] = SHA1CircularLeftShift(
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
            temp = SHA1CircularLeftShift(A, 5);
            temp += ((B & C) | ((~B) & D))
                + E
                + W[t]
                + 0x5a827999;
            E = D;
            D = C;
            C = SHA1CircularLeftShift(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 20; t < 40; ++t)
        {
            // f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)
            // K(t) = 6ED9EBA1         (20 <= t <= 39)
            temp = SHA1CircularLeftShift(A, 5);
            temp += (B ^ C ^ D)
                + E
                + W[t]
                + 0x6ed9eba1;
            E = D;
            D = C;
            C = SHA1CircularLeftShift(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 40; t < 60; ++t)
        {
            // f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
            // K(t) = 8F1BBCDC         (40 <= t <= 59)
            temp = SHA1CircularLeftShift(A, 5);
            temp += ((B & C) | (B & D) | (C & D))
                + E
                + W[t]
                + 0x8f1bbcdc;

            E = D;
            D = C;
            C = SHA1CircularLeftShift(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 60; t < 80; ++t)
        {
            temp = SHA1CircularLeftShift(A, 5);
            // f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79)
            // K(t) = CA62C1D6         (60 <= t <= 79).
            temp += (B ^ C ^ D)
                + E
                + W[t]
                + 0xca62c1d6;

            E = D;
            D = C;
            C = SHA1CircularLeftShift(B, 30);
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

internal void
SHA1ConstructDigest(sha1_context *context)
{
    sprintf(context->DigestStr,
            "%08x%08x%08x%08x%08x",
            context->H0,
            context->H1,
            context->H2,
            context->H3,
            context->H4);
}


internal sha1_context
SHA1HashString(char *messagePtr)
{
    const uint32 BLOCK_SIZE_BYTES = 64;     // 512 bits
    const uint32 BUFFER_SIZE_BYTES = 128;    // 1024 bits

    sha1_context result = {};
    uint64 byteCount = 0;

    while(*messagePtr != 0x00)
    {
        messagePtr++;
        result.MessageLengthBits += 8;
        byteCount++;

        // Process the message in blocks of 512 bits (64 bytes or sixteen 32-bit words)
        if(byteCount == BLOCK_SIZE_BYTES)
        {
            SHA1UpdateHash(&result, (uint8 *)(messagePtr - byteCount), byteCount);
            byteCount = 0;
        }
    }

    // Allocate a buffer to store the message remainder + padding + message length
    // Note (Aaron): We use a buffer length of 1024 bits to cover the worst case
    // scenario where extra padding is required (where the message remainder is
    // between 447 bits and 512 bits).
    uint8 buffer[BUFFER_SIZE_BYTES] = {};    // 1024 bits
    uint8 *bufferPtr = buffer;

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    memset(bufferPtr, 0xff, BUFFER_SIZE_BYTES);
#endif

    // The last 8 bytes are reserved to store the message length as a 64-bit integer
    bool useExtendedBuffer = (byteCount >= (BLOCK_SIZE_BYTES - 8));

    // Assert message remainder is small enough to fit into the buffer along with
    // padding and message length.
    Assert(byteCount < (BUFFER_SIZE_BYTES - 64 - 1));

    // Copy message remainder into the buffer
    MemoryCopy((uint8 *)(messagePtr - byteCount), bufferPtr, byteCount);

    // Apply padded 1
    uint8 *paddingPtr = bufferPtr + byteCount;
    *paddingPtr = (1 << 7);
    paddingPtr++;

    // Apply padded 0s
    // The last 8 bytes are reserved to store the message length as a 64-bit integer
    uint8 *paddingEndPtr = useExtendedBuffer
        ? bufferPtr + BUFFER_SIZE_BYTES - 8
        : bufferPtr + BLOCK_SIZE_BYTES - 8;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr = 0;
        paddingPtr++;
    }

    // Append length of message as a 64-bit number (in big endian)
    uint64 *sizePtr = (uint64 *)paddingPtr;
    uint64 messageLength64 = (uint64)result.MessageLengthBits;

    uint32 endianTest = 0xdeadbeef;
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

    // Apply final hash update
    byteCount = useExtendedBuffer ? BUFFER_SIZE_BYTES : BLOCK_SIZE_BYTES;
    SHA1UpdateHash(&result, bufferPtr, byteCount);

    SHA1ConstructDigest(&result);

    return result;
}

#define SHA1_H
#endif
