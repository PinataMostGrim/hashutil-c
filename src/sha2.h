#ifndef HASHUTIL_SHA2_H
#define HASHUTIL_SHA2_H

#include <stdint.h>

static uint32_t const HASHUTIL_SHA2_VERSION = 1;

static uint32_t const K_SHA256[] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

typedef struct sha2_256_context
{
    uint64_t MessageLengthBits;
    union
    {
        uint32_t H[8];
        struct
        {
            uint32_t H0;
            uint32_t H1;
            uint32_t H2;
            uint32_t H3;
            uint32_t H4;
            uint32_t H5;
            uint32_t H6;
            uint32_t H7;
        };
    };
    char DigestStr[65];

} sha2_256_context;

typedef enum sha256_digest_length
{
    SHA2_SHA256_224,
    SHA2_SHA256_256,
} sha256_digest_length;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA2_GetVersion();
sha2_256_context SHA2_HashStringSHA256(char *messagePtr, sha256_digest_length digestLength);

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA2_H
// end of header file ////////////////////////////////////////////////////////


#ifdef HASHUTIL_SHA2_IMPLEMENTATION

#include <stdio.h>
#include <stdbool.h>
#include "common.c"
#if HASHUTIL_SLOW
#include <string.h>
#endif

#define SHA2_SHA256_MESSAGE_STORAGE_SIZE_BYTES 8    // 64 bits
#define SHA2_SHA256_BLOCK_SIZE_BYTES 64             // 512 bits


#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA2_GetVersion()
{
    uint32_t result = HASHUTIL_SHA2_VERSION;
    return result;
}

static void SHA2_InitializeSHA224Context(sha2_256_context *context)
{
    context->MessageLengthBits = 0;

    context->H[0] = 0xc1059ed8;
    context->H[1] = 0x367cd507;
    context->H[2] = 0x3070dd17;
    context->H[3] = 0xf70e5939;
    context->H[4] = 0xffc00b31;
    context->H[5] = 0x68581511;
    context->H[6] = 0x64f98fa7;
    context->H[7] = 0xbefa4fa4;

#if HASHUTIL_SLOW
    memset(context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}

static void SHA2_InitializeSHA256Context(sha2_256_context *context)
{
    context->MessageLengthBits = 0;

    context->H[0] = 0x6a09e667;
    context->H[1] = 0xbb67ae85;
    context->H[2] = 0x3c6ef372;
    context->H[3] = 0xa54ff53a;
    context->H[4] = 0x510e527f;
    context->H[5] = 0x9b05688c;
    context->H[6] = 0x1f83d9ab;
    context->H[7] = 0x5be0cd19;

#if HASHUTIL_SLOW
    memset(context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}

uint32_t CH(uint32_t x, uint32_t y, uint32_t z)
{
    // CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
    return (x & y) ^ (~x & z);
}

uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z)
{
    // MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t BSIG0(uint32_t x)
{
    // BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

uint32_t BSIG1(uint32_t x)
{
    // BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

uint32_t SSIG0(uint32_t x)
{
    // SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

uint32_t SSIG1(uint32_t x)
{
    // SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

void SHA2_ApplyPaddingToMessageBlock(uint8_t *blockPtr, uint32_t blockSize,
                               char *messagePtr, uint64_t byteCount,
                               uint32_t messageLenthEncodingSize, uint64_t messageLengthBits)
{
    // We are expecting a buffer that can hold up to two message blocks
    Assert(blockSize % 2 == 0);

    // Message + padding + message length bits need to fit within the buffer
    Assert(byteCount <= blockSize - messageLenthEncodingSize - 1);

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    memset(blockPtr, 0xff, blockSize);
#endif

    uint32_t messageBlockSize = blockSize / 2;
    bool useFullBuffer = byteCount > (messageBlockSize - messageLenthEncodingSize - 1);

    // Apply the final hash update with padding
    // Copy message remainder (if any) into buffer
    if (byteCount > 0)
    {
        MemoryCopy(blockPtr, (uint8_t *)(messagePtr - byteCount), byteCount);
    }

    // Apply padded 1
    uint8_t *paddingPtr = blockPtr + byteCount;
    *paddingPtr++ = (1 << 7);

    // Apply padded 0s
    uint8_t *paddingEndPtr = blockPtr + ((useFullBuffer ? 2 : 1) * messageBlockSize) - messageLenthEncodingSize;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr++ = 0;
    }

    // Append length of message as a 64-bit number (in big endian)
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    uint64_t messageLength64 = messageLengthBits;

    if (IsSystemLittleEndian())
    {
        MirrorBits64(&messageLength64);
    }

    *sizePtr = messageLength64;
}

static void SHA2_UpdateSHA256Hash(sha2_256_context *context, uint8_t *messagePtr, uint64_t byteCount)
{
    // Assert that the message is divisible by 512-bits (64 bytes)
    Assert(byteCount % 64 == 0);

    uint32_t A, B, C, D, E, F, G, H;
#if HASHUTIL_SLOW
    A = 0;
    B = 0;
    C = 0;
    D = 0;
    E = 0;
    F = 0;
    G = 0;
    H = 0;
#endif

    uint32_t W[64];
#if HASHUTIL_SLOW
    memset(W, 0, sizeof(W));
#endif

    uint32_t t1 = 0;
    uint32_t t2 = 0;

    for(uint64_t i = 0; i < byteCount; i+=64)
    {
        // 'j' holds the word position from the start of the current block of 512 bits being processed
        // 16 words == 64 bytes == 512 bits
        for (int j = 0; j < 16; ++j)
        {
            // Convert from memory-order to message order. SHA256 is processed in 32bit words.
            // If it used 8-bit blocks, there would be no need to re-order the message chunks.
            W[j] = (uint32_t)(*(messagePtr + i + (j * 4)) << 24)
                 | (uint32_t)(*(messagePtr + i + (j * 4) + 1) << 16)
                 | (uint32_t)(*(messagePtr + i + (j * 4) + 2) << 8)
                 | (uint32_t)(*(messagePtr + i + (j * 4) + 3));
        }

        for (int t = 16; t < ArrayCount(W); ++t)
        {
            // Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
            W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
        }

        A = context->H0;
        B = context->H1;
        C = context->H2;
        D = context->H3;
        E = context->H4;
        F = context->H5;
        G = context->H6;
        H = context->H7;

        for (int t = 0; t < 64; ++t)
        {
            // T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
            t1 = H + BSIG1(E) + CH(E, F, G) + K_SHA256[t] + W[t];

            // T2 = BSIG0(a) + MAJ(a,b,c)
            t2 = BSIG0(A) + MAJ(A, B, C);

            H = G;
            G = F;
            F = E;
            E = D + t1;
            D = C;
            C = B;
            B = A;
            A = t1 + t2;
        }

        context->H0 += A;
        context->H1 += B;
        context->H2 += C;
        context->H3 += D;
        context->H4 += E;
        context->H5 += F;
        context->H6 += G;
        context->H7 += H;
    }
}

static void SHA2_ConstructSHA224Digest(sha2_256_context *context)
{
    // Assert buffer is large enough to hold a SHA224 digest
    // 224 bits in hex, plus the string null terminator character
    Assert(ArrayCount(context->DigestStr) >= (224 / 4 + 1))

    sprintf(context->DigestStr,
            "%08x%08x%08x%08x%08x%08x%08x",
            context->H[0],
            context->H[1],
            context->H[2],
            context->H[3],
            context->H[4],
            context->H[5],
            context->H[6]);
}

static void SHA2_ConstructSHA256Digest(sha2_256_context *context)
{
    // Assert buffer is large enough to hold a SHA256 digest
    // 256 bits in hex, plus the string null terminator character
    Assert(ArrayCount(context->DigestStr) >= (256 / 4 + 1));

    sprintf(context->DigestStr,
            "%08x%08x%08x%08x%08x%08x%08x%08x",
            context->H[0],
            context->H[1],
            context->H[2],
            context->H[3],
            context->H[4],
            context->H[5],
            context->H[6],
            context->H[7]);
}

sha2_256_context SHA2_HashStringSHA256(char *messagePtr, sha256_digest_length digestLength)
{

    sha2_256_context context;
    uint64_t byteCount = 0;

    switch (digestLength)
    {
        case SHA2_SHA256_224:
        {
            SHA2_InitializeSHA224Context(&context);
            break;
        }
        case SHA2_SHA256_256:
        default:
        {
            SHA2_InitializeSHA256Context(&context);
            break;
        }
    }

    while (*messagePtr != 0x00)
    {
        Assert(byteCount < SHA2_SHA256_BLOCK_SIZE_BYTES);

        messagePtr++;
        byteCount++;
        context.MessageLengthBits += 8;

        // Process the message in blocks of 512 bits (64 bytes or sixteen 32-bit words)
        if (byteCount == SHA2_SHA256_BLOCK_SIZE_BYTES)
        {
            SHA2_UpdateSHA256Hash(&context, (uint8_t *)messagePtr - byteCount, byteCount);
            byteCount = 0;
        }
    }

    // Allocate a buffer to store the final message block
    uint8_t buffer[SHA2_SHA256_BLOCK_SIZE_BYTES * 2];
    SHA2_ApplyPaddingToMessageBlock(buffer, ArrayCount(buffer),
                              messagePtr, byteCount,
                              SHA2_SHA256_MESSAGE_STORAGE_SIZE_BYTES, context.MessageLengthBits);

    bool useFullBuffer =
        byteCount > (SHA2_SHA256_BLOCK_SIZE_BYTES - SHA2_SHA256_MESSAGE_STORAGE_SIZE_BYTES - 1);
    byteCount = useFullBuffer ? (SHA2_SHA256_BLOCK_SIZE_BYTES * 2) : SHA2_SHA256_BLOCK_SIZE_BYTES;

    SHA2_UpdateSHA256Hash(&context, (uint8_t *)buffer, byteCount);

    switch (digestLength)
    {
        case SHA2_SHA256_224:
        {
            SHA2_ConstructSHA224Digest(&context);
            return context;
        }
        case SHA2_SHA256_256:
        default:
        {
            SHA2_ConstructSHA256Digest(&context);
            return context;
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA2_IMPLEMENTATION
