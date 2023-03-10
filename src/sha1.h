#if !defined(SHA1_H)

#include "hashutil.h"

#if HASHUTIL_SLOW
#include <string.h>
#endif

struct sha1_context
{
    uint32 MessageLengthBits = 0;
};


internal void
SHA1UpdateHash(sha1_context *context, uint8 *ptr, uint64 byteCount)
{
    // Assert that the message is divisible by 512-bits (64 bytes)
    Assert(byteCount % 64 == 0);
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
    memset(bufferPtr, 0xff, BUFFER_SIZE_BYTES);
#endif

    // The last 8 bytes are reserved to store the message length as a 64-bit integer
    bool useExtendedBuffer = (byteCount >= (BLOCK_SIZE_BYTES - 8));

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

    return result;
}

#define SHA1_H
#endif
