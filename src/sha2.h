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

static uint64_t const K_SHA512[] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

typedef struct uint128_t
{
    uint64_t High;
    uint64_t Low;
}uint128_t;

typedef enum sha2_message_block_size_bytes
{
    // Note (Aaron): Number of bytes in each message block
    sha2_message_block_sha256 = 64,             // 512 bits
    sha2_message_block_sha512 = 128,            // 1024 bits

} sha2_message_block_size_bytes;

typedef enum sha2_message_length_block_size_bytes
{
    // Note (Aaron): Number of bytes allocated for storing the length of the message
    sha2_message_length_block_sha256 = 8,       // 64 bits
    sha2_message_length_block_sha512 = 16,      // 128 bits

} sha2_message_length_block_size_bytes;

typedef struct sha2_message_padding_info
{
    uint8_t *BufferPtr;
    uint32_t BufferSizeBytes;
    sha2_message_block_size_bytes BlockSizeBytes;
    char *MessagePtr;
    uint64_t MessageSizeBytes;
    sha2_message_length_block_size_bytes MessageLengthBlockSizeBytes;

    // Note (Aaron): Total message size in bits. SHA512 supports message lengths stored in
    // 128-bit values so we use registers for high bits and low bits.
    uint64_t MessageLengthBitsHigh;
    uint64_t MessageLengthBitsLow;

}sha2_message_padding_info;

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

typedef struct sha2_512_context
{
    uint128_t MessageLengthBits;
    union
    {
        uint64_t H[8];
        struct
        {
            uint64_t H0;
            uint64_t H1;
            uint64_t H2;
            uint64_t H3;
            uint64_t H4;
            uint64_t H5;
            uint64_t H6;
            uint64_t H7;
        };
    };
    char DigestStr[129];

} sha2_512_context;

typedef enum sha2_digest_length_256
{
    SHA2_SHA256_224,
    SHA2_SHA256_256,
} sha2_digest_length_256;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA2_GetVersion();
sha2_256_context SHA2_HashStringSHA256(char *messagePtr, sha2_digest_length_256 digestLength);

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA2_H
// end of header file ////////////////////////////////////////////////////////


#ifdef HASHUTIL_SHA2_IMPLEMENTATION

#include <stdio.h>
#include <stdbool.h>
#include "common.c"


#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA2_GetVersion()
{
    uint32_t result = HASHUTIL_SHA2_VERSION;
    return result;
}

static void SHA2_InitializeContextSHA224(sha2_256_context *context)
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
    MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}

static void SHA2_InitializeContextSHA256(sha2_256_context *context)
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
    MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}

static void SHA2_InitializeContextSHA512(sha2_512_context *context)
{
    context->MessageLengthBits.High = 0;
    context->MessageLengthBits.Low = 0;

    context->H[0]= 0x6a09e667f3bcc908;
    context->H[1]= 0xbb67ae8584caa73b;
    context->H[2]= 0x3c6ef372fe94f82b;
    context->H[3]= 0xa54ff53a5f1d36f1;
    context->H[4]= 0x510e527fade682d1;
    context->H[5]= 0x9b05688c2b3e6c1f;
    context->H[6]= 0x1f83d9abfb41bd6b;
    context->H[7]= 0x5be0cd19137e2179;

#if HASHUTIL_SLOW
    MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
#endif
}

void IncrementUINT128(uint128_t *value, int64_t increment)
{
    uint64_t low = value->Low;
    value->Low += increment;

    if (increment > 0 && value->Low < low)
    {
        value->High++;
    }
    else if (increment < 0 && value->Low > low)
    {
        value->High--;
    }
}

uint32_t CH_SHA256(uint32_t x, uint32_t y, uint32_t z)
{
    // CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
    return (x & y) ^ (~x & z);
}

uint32_t MAJ_SHA256(uint32_t x, uint32_t y, uint32_t z)
{
    // MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t BSIG0_SHA256(uint32_t x)
{
    // BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    return ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22);
}

uint32_t BSIG1_SHA256(uint32_t x)
{
    // BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    return ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25);
}

uint32_t SSIG0_SHA256(uint32_t x)
{
    // SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    return ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3);
}

uint32_t SSIG1_SHA256(uint32_t x)
{
    // SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    return ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10);
}

uint64_t CH_SHA512(uint64_t x, uint64_t y, uint64_t z)
{
    // CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
    return (x & y) ^ (~x & z);
}

uint64_t MAJ_SHA512(uint64_t x, uint64_t y, uint64_t z)
{
    // MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    return (x & y) ^ (x & z) ^ (y & z);
}

uint64_t BSIG0_SHA512(uint64_t x)
{
    // BSIG0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
    return ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39);
}

uint64_t BSIG1_SHA512(uint64_t x)
{
    // BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
    return ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41);
}

uint64_t SSIG0_SHA512(uint64_t x)
{
    // SSIG0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
    return ROTR64(x, 1) ^ ROTR64(x, 8) ^ (x >> 7);
}

uint64_t SSIG1_SHA512(uint64_t x)
{
    // SSIG1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
    return ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6);
}

void SHA2_ApplyPadding(sha2_message_padding_info messageInfo)
{
    // We are expecting a buffer that can hold up to two message blocks
    Assert(messageInfo.BufferSizeBytes / messageInfo.BlockSizeBytes == 2);

    // Message + padding + message length bits need to fit within the buffer
    Assert(messageInfo.MessageSizeBytes <= (messageInfo.BufferSizeBytes - messageInfo.MessageLengthBlockSizeBytes - 1));

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    MemorySet((uint8_t *)messageInfo.BufferPtr, 0xff, messageInfo.BufferSizeBytes);
#endif

    bool useFullBuffer = messageInfo.MessageSizeBytes > (messageInfo.BlockSizeBytes - messageInfo.MessageLengthBlockSizeBytes - 1);

    // Apply the final hash update with padding
    // Copy message remainder (if any) into buffer
    if (messageInfo.MessageSizeBytes > 0)
    {
        MemoryCopy(messageInfo.BufferPtr, (uint8_t *)(messageInfo.MessagePtr - messageInfo.MessageSizeBytes), messageInfo.MessageSizeBytes);
    }

    // Apply padded 1
    uint8_t *paddingPtr = messageInfo.BufferPtr + messageInfo.MessageSizeBytes;
    *paddingPtr++ = (1 << 7);

    // Apply padded 0s
    uint8_t *paddingEndPtr = messageInfo.BufferPtr
        + ((useFullBuffer ? 2 : 1) * messageInfo.BlockSizeBytes)
        - messageInfo.MessageLengthBlockSizeBytes;

    while (paddingPtr < paddingEndPtr)
    {
        *paddingPtr++ = 0;
    }

    // Append length of message in bits (in big endian)
    uint64_t *sizePtr = (uint64_t *)paddingPtr;
    uint64_t messageLengthBitsHigh = messageInfo.MessageLengthBitsHigh;
    uint64_t messageLengthBitsLow = messageInfo.MessageLengthBitsLow;

    if (IsSystemLittleEndian())
    {
        MirrorBits64(&messageLengthBitsHigh);
        MirrorBits64(&messageLengthBitsLow);
    }

    switch(messageInfo.MessageLengthBlockSizeBytes)
    {
        case sha2_message_length_block_sha256:
        {
            *sizePtr = messageLengthBitsLow;
            break;
        }
        case sha2_message_length_block_sha512:
        {
            *sizePtr = messageLengthBitsHigh;
            sizePtr+=1;
            *sizePtr = messageLengthBitsLow;
            break;
        }
    }
}

static void SHA2_UpdateHashSHA256(sha2_256_context *context, uint8_t *messagePtr, uint64_t messageByteCount)
{
    // Assert that the message is divisible by 512-bits (64 bytes)
    Assert(messageByteCount % sha2_message_block_sha256 == 0);

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
    MemorySet((uint8_t *)W, 0, sizeof(W));
#endif

    uint32_t t1 = 0;
    uint32_t t2 = 0;

    for(uint64_t i = 0; i < messageByteCount; i+=sha2_message_block_sha256)
    {
        // 'j' holds the word position from the start of the current block of 512 bits being processed
        // 16 words == 64 bytes == 512 bits
        for (int j = 0; j < 16; ++j)
        {
            // Convert from memory-order to message order. SHA256 is processed in 32bit words.
            // If it used 8-bit blocks, there would be no need to re-order the message chunks.
            W[j] = ((uint32_t)*(messagePtr + i + (j * 4)) << 24)
                 | ((uint32_t)*(messagePtr + i + (j * 4) + 1) << 16)
                 | ((uint32_t)*(messagePtr + i + (j * 4) + 2) << 8)
                 | ((uint32_t)*(messagePtr + i + (j * 4) + 3));
        }

        for (int t = 16; t < ArrayCount(W); ++t)
        {
            // Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
            W[t] = SSIG1_SHA256(W[t-2]) + W[t-7] + SSIG0_SHA256(W[t-15]) + W[t-16];
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
            t1 = H + BSIG1_SHA256(E) + CH_SHA256(E, F, G) + K_SHA256[t] + W[t];

            // T2 = BSIG0_SHA256(a) + MAJ_SHA256(a,b,c)
            t2 = BSIG0_SHA256(A) + MAJ_SHA256(A, B, C);

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

static void SHA2_UpdateHashSHA512(sha2_512_context *context, uint8_t *messagePtr, uint64_t byteCount)
{
    // Assert that the message is divisible by 1024-bits (128 bytes)
    Assert(byteCount % sha2_message_block_sha512 == 0);

    uint64_t A, B, C, D, E, F, G, H;
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

    uint64_t W[80];
#if HASHUTIL_SLOW
    MemorySet((uint8_t *)W, 0, sizeof(W));
#endif

    uint64_t t1 = 0;
    uint64_t t2 = 0;

    for(uint64_t i = 0; i < byteCount; i+=sha2_message_block_sha512)
    {
        // 'j' holds the word position from the start of the current block of 1024 bits being processed
        for (int j = 0; j < 16; ++j)
        {
            W[j] = ((uint64_t)*(messagePtr + i + (j * 8) + 0) << 56)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 1) << 48)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 2) << 40)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 3) << 32)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 4) << 24)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 5) << 16)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 6) << 8)
                | ((uint64_t)*(messagePtr + i + (j * 8) + 7));
        }

        for (int t = 16; t < ArrayCount(W); ++t)
        {
            // Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(W(t-15)) + W(t-16)
            W[t] = SSIG1_SHA512(W[t-2]) + W[t-7] + SSIG0_SHA512(W[t-15]) + W[t-16];
        }

        A = context->H0;
        B = context->H1;
        C = context->H2;
        D = context->H3;
        E = context->H4;
        F = context->H5;
        G = context->H6;
        H = context->H7;

        for (int t = 0; t < ArrayCount(W); ++t)
        {
            // T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
            t1 = H + BSIG1_SHA512(E) + CH_SHA512(E, F, G) + K_SHA512[t] + W[t];

            // T2 = BSIG0(a) + MAJ(a,b,c)
            t2 = BSIG0_SHA512(A) + MAJ_SHA512(A, B, C);

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

static void SHA2_ConstructDigestSHA224(sha2_256_context *context)
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

static void SHA2_ConstructDigestSHA256(sha2_256_context *context)
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

static void SHA2_ConstructDigestSHA512(sha2_512_context *context)
{
    // Assert buffer is large enough to hold a SHA256 digest
    // 256 bits in hex, plus the string null terminator character
    Assert(ArrayCount(context->DigestStr) >= (512 / 4 + 1));

    sprintf(context->DigestStr,
            "%016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx",
            context->H[0],
            context->H[1],
            context->H[2],
            context->H[3],
            context->H[4],
            context->H[5],
            context->H[6],
            context->H[7]);
}

sha2_256_context SHA2_HashStringSHA256(char *messagePtr, sha2_digest_length_256 digestLength)
{

    sha2_256_context context;
    uint64_t messageByteCount = 0;

    switch (digestLength)
    {
        case SHA2_SHA256_224:
        {
            SHA2_InitializeContextSHA224(&context);
            break;
        }
        case SHA2_SHA256_256:
        default:
        {
            SHA2_InitializeContextSHA256(&context);
            break;
        }
    }

    while (*messagePtr != 0x00)
    {
        Assert(messageByteCount < sha2_message_block_sha256);

        messagePtr++;
        messageByteCount++;
        context.MessageLengthBits += 8;

        // Process the message in blocks of 512 bits (64 bytes or sixteen 32-bit words)
        if (messageByteCount == sha2_message_block_sha256)
        {
            SHA2_UpdateHashSHA256(&context, (uint8_t *)messagePtr - messageByteCount, messageByteCount);
            messageByteCount = 0;
        }
    }

    // Allocate a buffer to store the final message block
    uint8_t buffer[sha2_message_block_sha256 * 2];

    // Apply padding to the final message block(s)
    sha2_message_padding_info messageInfo =
    {
        messageInfo.BufferPtr = buffer,
        messageInfo.BufferSizeBytes = ArrayCount(buffer),
        messageInfo.BlockSizeBytes = sha2_message_block_sha256,
        messageInfo.MessagePtr = messagePtr,
        messageInfo.MessageSizeBytes = messageByteCount,
        messageInfo.MessageLengthBlockSizeBytes = sha2_message_length_block_sha256,
        messageInfo.MessageLengthBitsHigh = 0,
        messageInfo.MessageLengthBitsLow = context.MessageLengthBits,
    };
    SHA2_ApplyPadding(messageInfo);

    // Apply final hash computation
    bool useFullBuffer = messageByteCount > (sha2_message_block_sha256 - sha2_message_length_block_sha256 - 1);
    messageByteCount = useFullBuffer ? (sha2_message_block_sha256 * 2) : sha2_message_block_sha256;
    SHA2_UpdateHashSHA256(&context, (uint8_t *)buffer, messageByteCount);

    switch (digestLength)
    {
        case SHA2_SHA256_224:
        {
            SHA2_ConstructDigestSHA224(&context);
            return context;
        }
        case SHA2_SHA256_256:
        default:
        {
            SHA2_ConstructDigestSHA256(&context);
            return context;
        }
    }
}

sha2_512_context SHA2_HashStringSHA512(char *messagePtr)
{
    sha2_512_context context;
    uint16_t messageByteCount = 0;

    SHA2_InitializeContextSHA512(&context);

    while (*messagePtr != 0x00)
    {
        Assert(messageByteCount < sha2_message_block_sha512);

        messagePtr++;
        messageByteCount++;
        IncrementUINT128(&context.MessageLengthBits, 8);

        // Process the message in blocks of 1024 bits (128 bytes or sixteen 64-bit words)
        if (messageByteCount == sha2_message_block_sha512)
        {
            SHA2_UpdateHashSHA512(&context, (uint8_t *)messagePtr - messageByteCount, messageByteCount);
            messageByteCount = 0;
        }
    }

    // Allocate a buffer to store the final message block
    uint8_t buffer[sha2_message_block_sha512 * 2];

    // Apply padding to the final message blocks(s)
    sha2_message_padding_info messageInfo =
    {
        messageInfo.BufferPtr = buffer,
        messageInfo.BufferSizeBytes = ArrayCount(buffer),
        messageInfo.BlockSizeBytes = sha2_message_block_sha512,
        messageInfo.MessagePtr = messagePtr,
        messageInfo.MessageSizeBytes = messageByteCount,
        messageInfo.MessageLengthBlockSizeBytes = sha2_message_length_block_sha512,
        messageInfo.MessageLengthBitsHigh = context.MessageLengthBits.High,
        messageInfo.MessageLengthBitsLow = context.MessageLengthBits.Low,
    };
    SHA2_ApplyPadding(messageInfo);

    // Apply final hash computation
    bool useFullBuffer = messageByteCount > (sha2_message_block_sha512 - sha2_message_length_block_sha512 - 1);
    messageByteCount = useFullBuffer ? (sha2_message_block_sha512 * 2) : sha2_message_block_sha512;
    SHA2_UpdateHashSHA512(&context, (uint8_t *)buffer, messageByteCount);
    SHA2_ConstructDigestSHA512(&context);

    return context;
}

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA2_IMPLEMENTATION
