#ifndef HASHUTIL_SHA2_H
#define HASHUTIL_SHA2_H

#include <stdint.h>
#include <stdbool.h>

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

typedef struct
{
    uint64_t High;
    uint64_t Low;
}uint128_t;

// Number of bytes in each message block
typedef enum
{
    SHA2_MESSAGE_BLOCK_SIZE_SHA256 = 64,             // 512 bits
    SHA2_MESSAGE_BLOCK_SIZE_SHA512 = 128,            // 1024 bits
} sha2_message_block_size_bytes;

// Number of bytes allocated for storing the length of the message
typedef enum
{
    SHA2_MESSAGE_LENGTH_BLOCK_SHA256 = 8,       // 64 bits
    SHA2_MESSAGE_LENGTH_BLOCK_SHA512 = 16,      // 128 bits
} sha2_message_length_block_size_bytes;

typedef enum
{
    SHA2_DIGEST_LENGTH_SHA224 = 224,
    SHA2_DIGEST_LENGTH_SHA256 = 256,
    SHA2_DIGEST_LENGTH_SHA384 = 384,
    SHA2_DIGEST_LENGTH_SHA512 = 512,
} sha2_digest_length;

typedef struct
{
    uint8_t *BufferPtr;
    size_t BufferSizeBytes;
    sha2_message_block_size_bytes BlockSizeBytes;
    uint64_t MessageRemainderSizeBytes;
    sha2_message_length_block_size_bytes MessageLengthBlockSizeBytes;

    // Note (Aaron): Total message size in bits. SHA512 supports message lengths stored in
    // 128-bit values so we use registers for high bits and low bits and combine them.
    uint64_t MessageLengthBitsHigh;
    uint64_t MessageLengthBitsLow;
}sha2_message_padding_info;

typedef struct
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
    bool Error;
    char ErrorStr[64];
} sha2_256_context;

typedef struct
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
    bool Error;
    char ErrorStr[64];
} sha2_512_context;


#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA2_GetVersion();
sha2_256_context SHA2_HashStringSHA224(char *messagePtr);
sha2_256_context SHA2_HashStringSHA256(char *messagePtr);
sha2_256_context SHA2_HashFileSHA224(char *fileName);
sha2_256_context SHA2_HashFileSHA256(char *fileName);

sha2_512_context SHA2_HashStringSHA512_224(char *messagePtr);
sha2_512_context SHA2_HashStringSHA512_256(char *messagePtr);
sha2_512_context SHA2_HashStringSHA384(char *messagePtr);
sha2_512_context SHA2_HashStringSHA512(char *messagePtr);
sha2_512_context SHA2_HashFileSHA512_224(char *fileName);
sha2_512_context SHA2_HashFileSHA512_256(char *fileName);
sha2_512_context SHA2_HashFileSHA384(char *fileName);
sha2_512_context SHA2_HashFileSHA512(char *fileName);

#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA2_H
// end of header file ////////////////////////////////////////////////////////


#ifdef HASHUTIL_SHA2_IMPLEMENTATION

#include <stdio.h>
#include <stdbool.h>

#if HASHUTIL_SLOW
#include <assert.h>
#define sha2_static_assert(expression, string) static_assert(expression, string)
#define sha2_assert(expression) assert(expression)
#else
#define sha2_static_assert(expression, string)
#define sha2_assert(expression)
#endif

#define SHA2_ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t SHA2_GetVersion()
{
    uint32_t result = HASHUTIL_SHA2_VERSION;
    return result;
}

static void *SHA2_MemoryCopy(void *destPtr, void const *sourcePtr, size_t size)
{
    sha2_assert(size > 0);

    unsigned char *source = (unsigned char *)sourcePtr;
    unsigned char *dest = (unsigned char *)destPtr;
    while(size--) *dest++ = *source++;

    return destPtr;
}

static void *SHA2_MemorySet(uint8_t *destPtr, int c, size_t count)
{
    sha2_assert(count > 0);

    unsigned char *dest = (unsigned char *)destPtr;
    while(count--) *dest++ = (unsigned char)c;

    return destPtr;
}

// 32-bit Circular bit shift right
static uint32_t SHA2_ROTR32(uint32_t value, uint8_t count)
{
    return (value >> count) | (value << (32 - count));
}

// 64-bit Circular bit shift right
static uint64_t SHA2_ROTR64(uint64_t value, uint8_t count)
{
    return (value >> count) | (value << (64 - count));
}

// Swap endianness of 64 bit value
static void SHA2_MirrorBits64(uint64_t *bits)
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

static bool SHA2_IsSystemLittleEndian()
{
    uint32_t endianTest = 0xdeadbeef;
    bool isLittleEndian = *(unsigned char *)&endianTest = 0xef;

    return isLittleEndian;
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

    context->Error = false;

#if HASHUTIL_SLOW
    SHA2_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    SHA2_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
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

    context->Error = false;

#if HASHUTIL_SLOW
    SHA2_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    SHA2_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
#endif
}

static void SHA2_InitializeContextSHA512_224(sha2_512_context *context)
{
    context->MessageLengthBits.High = 0;
    context->MessageLengthBits.Low = 0;

    context->H[0]= 0x8c3d37c819544da2;
    context->H[1]= 0x73e1996689dcd4d6;
    context->H[2]= 0x1dfab7ae32ff9c82;
    context->H[3]= 0x679dd514582f9fcf;
    context->H[4]= 0x0f6d2b697bd44da8;
    context->H[5]= 0x77e36f7304c48942;
    context->H[6]= 0x3f9d85a86a1d36c8;
    context->H[7]= 0x1112e6ad91d692a1;

    context->Error = false;

#if HASHUTIL_SLOW
    SHA2_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    SHA2_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
#endif
}

static void SHA2_InitializeContextSHA512_256(sha2_512_context *context)
{
    context->MessageLengthBits.High = 0;
    context->MessageLengthBits.Low = 0;

    context->H[0]= 0x22312194fc2bf72c;
    context->H[1]= 0x9f555fa3c84c64c2;
    context->H[2]= 0x2393b86b6f53b151;
    context->H[3]= 0x963877195940eabd;
    context->H[4]= 0x96283ee2a88effe3;
    context->H[5]= 0xbe5e1e2553863992;
    context->H[6]= 0x2b0199fc2c85b8aa;
    context->H[7]= 0x0eb72ddc81c52ca2;

    context->Error = false;

#if HASHUTIL_SLOW
    SHA2_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    SHA2_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
#endif
}

static void SHA2_InitializeContextSHA384(sha2_512_context *context)
{
    context->MessageLengthBits.High = 0;
    context->MessageLengthBits.Low = 0;

    context->H[0]= 0xcbbb9d5dc1059ed8;
    context->H[1]= 0x629a292a367cd507;
    context->H[2]= 0x9159015a3070dd17;
    context->H[3]= 0x152fecd8f70e5939;
    context->H[4]= 0x67332667ffc00b31;
    context->H[5]= 0x8eb44a8768581511;
    context->H[6]= 0xdb0c2e0d64f98fa7;
    context->H[7]= 0x47b5481dbefa4fa4;

    context->Error = false;

#if HASHUTIL_SLOW
    SHA2_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    SHA2_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
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

    context->Error = false;

#if HASHUTIL_SLOW
    SHA2_MemorySet((uint8_t *)context->DigestStr, 0, sizeof(context->DigestStr));
    SHA2_MemorySet((uint8_t *)context->ErrorStr, 0, sizeof(context->ErrorStr));
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

bool UINT128GreaterThan(uint128_t lhv, uint128_t rhv)
{
    if (lhv.High > rhv.High)
    {
        return true;
    }

    if (lhv.High < rhv.High)
    {
        return false;
    }

    return lhv.Low > rhv.Low;
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
    return SHA2_ROTR32(x, 2) ^ SHA2_ROTR32(x, 13) ^ SHA2_ROTR32(x, 22);
}

uint32_t BSIG1_SHA256(uint32_t x)
{
    // BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    return SHA2_ROTR32(x, 6) ^ SHA2_ROTR32(x, 11) ^ SHA2_ROTR32(x, 25);
}

uint32_t SSIG0_SHA256(uint32_t x)
{
    // SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    return SHA2_ROTR32(x, 7) ^ SHA2_ROTR32(x, 18) ^ (x >> 3);
}

uint32_t SSIG1_SHA256(uint32_t x)
{
    // SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    return SHA2_ROTR32(x, 17) ^ SHA2_ROTR32(x, 19) ^ (x >> 10);
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
    return SHA2_ROTR64(x, 28) ^ SHA2_ROTR64(x, 34) ^ SHA2_ROTR64(x, 39);
}

uint64_t BSIG1_SHA512(uint64_t x)
{
    // BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
    return SHA2_ROTR64(x, 14) ^ SHA2_ROTR64(x, 18) ^ SHA2_ROTR64(x, 41);
}

uint64_t SSIG0_SHA512(uint64_t x)
{
    // SSIG0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
    return SHA2_ROTR64(x, 1) ^ SHA2_ROTR64(x, 8) ^ (x >> 7);
}

uint64_t SSIG1_SHA512(uint64_t x)
{
    // SSIG1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
    return SHA2_ROTR64(x, 19) ^ SHA2_ROTR64(x, 61) ^ (x >> 6);
}

void SHA2_ApplyPadding(sha2_message_padding_info messageInfo)
{
    // We are expecting a buffer that can hold up to two message blocks
    sha2_assert(messageInfo.BufferSizeBytes / messageInfo.BlockSizeBytes == 2);

    // Message + padding + message length bits need to fit within the buffer
    sha2_assert(messageInfo.MessageLengthBlockSizeBytes
                <= (messageInfo.BufferSizeBytes - messageInfo.MessageLengthBlockSizeBytes - 1));

    bool useFullBuffer = messageInfo.MessageRemainderSizeBytes
                         > (messageInfo.BlockSizeBytes - messageInfo.MessageLengthBlockSizeBytes - 1);

    // Apply padded 1
    uint8_t *paddingPtr = messageInfo.BufferPtr + messageInfo.MessageRemainderSizeBytes;
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

    if (SHA2_IsSystemLittleEndian())
    {
        SHA2_MirrorBits64(&messageLengthBitsHigh);
        SHA2_MirrorBits64(&messageLengthBitsLow);
    }

    switch(messageInfo.MessageLengthBlockSizeBytes)
    {
        case SHA2_MESSAGE_LENGTH_BLOCK_SHA256:
        {
            *sizePtr = messageLengthBitsLow;
            break;
        }
        case SHA2_MESSAGE_LENGTH_BLOCK_SHA512:
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
    sha2_assert(messageByteCount % SHA2_MESSAGE_BLOCK_SIZE_SHA256 == 0);

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
    SHA2_MemorySet((uint8_t *)W, 0, sizeof(W));
#endif

    uint32_t t1 = 0;
    uint32_t t2 = 0;

    for(uint64_t i = 0; i < messageByteCount; i+=SHA2_MESSAGE_BLOCK_SIZE_SHA256)
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

        for (int t = 16; t < SHA2_ArrayCount(W); ++t)
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
    // Note (Aaron): Using a uint64_t type for 'byteCount' limits the maximum amount of data that can be
    // passed through this method on one invocation to less than what the algorithm can support  but that's
    // fine as it would be in the Pebibyte range and totally impractical.

    // Assert that the message is divisible by 1024-bits (128 bytes)
    sha2_assert(byteCount % SHA2_MESSAGE_BLOCK_SIZE_SHA512 == 0);

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
    SHA2_MemorySet((uint8_t *)W, 0, sizeof(W));
#endif

    uint64_t t1 = 0;
    uint64_t t2 = 0;

    for(uint64_t i = 0; i < byteCount; i+=SHA2_MESSAGE_BLOCK_SIZE_SHA512)
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

        for (int t = 16; t < SHA2_ArrayCount(W); ++t)
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

        for (int t = 0; t < SHA2_ArrayCount(W); ++t)
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
    // (224 bits in hex, plus the string null terminator character)
    sha2_static_assert(SHA2_ArrayCount(context->DigestStr) >= (224 / 4 + 1),
                  "Buffer is not large enough to hold SHA224 digest");

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
    // (256 bits in hex, plus the string null terminator character)
    sha2_static_assert(SHA2_ArrayCount(context->DigestStr) >= (256 / 4 + 1),
                  "Buffer is not large enough to hold SHA256 digest");

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

static void SHA2_ConstructDigestSHA512_224(sha2_512_context *context)
{
    // Assert buffer is large enough to hold a SHA512/224 digest
    // (224 bits in hex, plus the string null terminator character)
    sha2_static_assert(SHA2_ArrayCount(context->DigestStr) >= (224 / 4 + 1),
                  "Buffer is not large enough to hold SHA512/224 digest");

    sprintf(context->DigestStr,
            "%016llx%016llx%016llx%08llx",
            context->H[0],
            context->H[1],
            context->H[2],
            (context->H[3] >> 32));
}

static void SHA2_ConstructDigestSHA512_256(sha2_512_context *context)
{
    // Assert buffer is large enough to hold a SHA512/256 digest
    // (256 bits in hex, plus the string null terminator character)
    sha2_static_assert(SHA2_ArrayCount(context->DigestStr) >= (256 / 4 + 1),
                  "Buffer is not large enough to hold SHA512/256 digest");

    sprintf(context->DigestStr,
            "%016llx%016llx%016llx%016llx",
            context->H[0],
            context->H[1],
            context->H[2],
            context->H[3]);
}

static void SHA2_ConstructDigestSHA384(sha2_512_context *context)
{
    // Assert buffer is large enough to hold a SHA384 digest
    // (384 bits in hex, plus the string null terminator character)
    sha2_static_assert(SHA2_ArrayCount(context->DigestStr) >= (384 / 4 + 1),
                  "Buffer is not large enough to hold SHA384 digest");

    sprintf(context->DigestStr,
            // TODO (Aaron): Look up this formatting to make sure it is correct
            "%016llx%016llx%016llx%016llx%016llx%016llx",
            context->H[0],
            context->H[1],
            context->H[2],
            context->H[3],
            context->H[4],
            context->H[5]);
}

static void SHA2_ConstructDigestSHA512(sha2_512_context *context)
{
    // Assert buffer is large enough to hold a SHA512 digest
    // (512 bits in hex, plus the string null terminator character)
    sha2_static_assert(SHA2_ArrayCount(context->DigestStr) >= (512 / 4 + 1),
                  "Buffer is not large enough to hold SHA512 digest");

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

sha2_256_context SHA2_HashStringSHA256_(char *messagePtr, sha2_digest_length digestLength)
{
    sha2_256_context context;
    uint8_t messageBlockByteCount = 0;
    sha2_static_assert(UINT8_MAX > (SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2),
                       "messageBlockByteCount cannot fit within a uint8_t\n");

    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_InitializeContextSHA224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_InitializeContextSHA256(&context);
            break;
        }
        default:
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid digest length for SHA256: %i", digestLength);
            sprintf(context.DigestStr, "");
            return context;
        }
    }

    while (*messagePtr != 0x00)
    {
        sha2_assert(messageBlockByteCount < SHA2_MESSAGE_BLOCK_SIZE_SHA256);
        uint64_t oldMessageLengthBits = context.MessageLengthBits;

        messagePtr++;
        messageBlockByteCount++;
        context.MessageLengthBits += 8;

        if (context.MessageLengthBits < oldMessageLengthBits)
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid message length: larger than 2^64 bits");
            sprintf(context.DigestStr, "");
            return context;
        }

        // Process the message in blocks of 512 bits (64 bytes or sixteen 32-bit words)
        if (messageBlockByteCount == SHA2_MESSAGE_BLOCK_SIZE_SHA256)
        {
            SHA2_UpdateHashSHA256(&context, (uint8_t *)messagePtr - messageBlockByteCount, messageBlockByteCount);
            messageBlockByteCount = 0;
        }
    }

    // Allocate a buffer to store the final message block
    uint8_t buffer[SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2];
    uint8_t bufferSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2;
    sha2_static_assert(UINT8_MAX > (SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2),
                       "bufferSizeBytes cannot fit within a uint8_t\n");

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    SHA2_MemorySet(buffer, 0xff, bufferSizeBytes);
#endif

    // Copy message remainder (if any) into buffer
    if (messageBlockByteCount > 0)
    {
        SHA2_MemoryCopy(buffer, (uint8_t *)(messagePtr - messageBlockByteCount), messageBlockByteCount);
    }

    // Apply padding to the final message block(s)
    sha2_message_padding_info messageInfo =
    {
        messageInfo.BufferPtr = buffer,
        messageInfo.BufferSizeBytes = bufferSizeBytes,
        messageInfo.BlockSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA256,
        messageInfo.MessageRemainderSizeBytes = messageBlockByteCount,
        messageInfo.MessageLengthBlockSizeBytes = SHA2_MESSAGE_LENGTH_BLOCK_SHA256,
        messageInfo.MessageLengthBitsHigh = 0,
        messageInfo.MessageLengthBitsLow = context.MessageLengthBits,
    };

    SHA2_ApplyPadding(messageInfo);

    // Apply final hash computation
    bool useFullBuffer = messageBlockByteCount > (SHA2_MESSAGE_BLOCK_SIZE_SHA256 - SHA2_MESSAGE_LENGTH_BLOCK_SHA256 - 1);
    messageBlockByteCount = useFullBuffer ? (bufferSizeBytes) : SHA2_MESSAGE_BLOCK_SIZE_SHA256;
    SHA2_UpdateHashSHA256(&context, (uint8_t *)buffer, messageBlockByteCount);

    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_ConstructDigestSHA224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_ConstructDigestSHA256(&context);
            break;
        }
        default:
        {
            // Invalid digest length for SHA256. We should never reach this state here.
            sha2_assert(false);
        }
    }

    return context;
}

sha2_256_context SHA2_HashFileSHA256_(char *fileName, sha2_digest_length digestLength)
{
    sha2_256_context context;
    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_InitializeContextSHA224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_InitializeContextSHA256(&context);
            break;
        }
        default:
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid digest length for SHA256: %i", digestLength);
            sprintf(context.DigestStr, "");
            return context;
        }
    }

    FILE *file = fopen(fileName, "rb");
    if (!file)
    {
        sha2_assert(false);

        context.Error = true;
        sprintf(context.ErrorStr, "Unable to open file");
        sprintf(context.DigestStr, "");
        return context;
    }

    // Note (Aaron): Create a buffer that can hold two full message blocks as
    // we will potentially use the extra space when applying padding later.
    uint8_t buffer[SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2];
    uint8_t *bufferPtr = buffer;
    uint8_t bufferSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2;
    sha2_static_assert(UINT8_MAX > (SHA2_MESSAGE_BLOCK_SIZE_SHA256 * 2),
                       "bufferSizeBytes cannot fit within a uint8_t\n");

#if HASHUTIL_SLOW
    SHA2_MemorySet(bufferPtr, 0xff, bufferSizeBytes);
#endif

    size_t readElementSize = sizeof(uint8_t);
    size_t readBlockSize = sizeof(uint8_t) * SHA2_MESSAGE_BLOCK_SIZE_SHA256;
    uint64_t blockBytesRead = 0;

    // Note (Aaron): Sanity check
    sha2_assert(readElementSize == 1);

    // Update hash using file contents until we run out of blocks of sufficient size
    blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
    while(blockBytesRead)
    {
        sha2_assert(blockBytesRead <= SHA2_MESSAGE_BLOCK_SIZE_SHA256);
        uint64_t oldMessageLengthBits = context.MessageLengthBits;

        context.MessageLengthBits += (blockBytesRead * 8);
        if (context.MessageLengthBits < oldMessageLengthBits)
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid file size: larger than 2^64 bits");
            sprintf(context.DigestStr, "");
            return context;
        }

        if(blockBytesRead == SHA2_MESSAGE_BLOCK_SIZE_SHA256)
        {
            SHA2_UpdateHashSHA256(&context, bufferPtr, blockBytesRead);
            blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
            continue;
        }

        // Note (Aaron): If we ever read less bytes than SHA2_MESSAGE_LENGTH_BLOCK_SHA256,
        // it is time to stop reading the file and apply padding.
        break;
    }

    if (ferror(file))
    {
        fclose(file);
        sha2_assert(false);

        context.Error = true;
        sprintf(context.ErrorStr, "Error reading file");
        sprintf(context.DigestStr, "");
        return context;
    }

    fclose(file);

    // Apply the final hash update with padding
    sha2_message_padding_info messageInfo =
    {
        messageInfo.BufferPtr = buffer,
        messageInfo.BufferSizeBytes = bufferSizeBytes,
        messageInfo.BlockSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA256,
        messageInfo.MessageRemainderSizeBytes = blockBytesRead,
        messageInfo.MessageLengthBlockSizeBytes = SHA2_MESSAGE_LENGTH_BLOCK_SHA256,
        messageInfo.MessageLengthBitsHigh = 0,
        messageInfo.MessageLengthBitsLow = context.MessageLengthBits,
    };

    SHA2_ApplyPadding(messageInfo);

    bool useFullBuffer = blockBytesRead > (SHA2_MESSAGE_BLOCK_SIZE_SHA256 - SHA2_MESSAGE_LENGTH_BLOCK_SHA256 - 1);
    blockBytesRead = useFullBuffer ? (bufferSizeBytes) : SHA2_MESSAGE_BLOCK_SIZE_SHA256;
    SHA2_UpdateHashSHA256(&context, buffer, blockBytesRead);

    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_ConstructDigestSHA224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_ConstructDigestSHA256(&context);
            break;
        }
        default:
        {
            // Invalid digest length for SHA256. We should never reach this state here.
            sha2_assert(false);
        }
    }

    return context;
}

sha2_512_context SHA2_HashStringSHA512_(char *messagePtr, sha2_digest_length digestLength)
{
    sha2_512_context context;
    uint16_t messageBlockByteCount = 0;
    sha2_static_assert(UINT16_MAX > (SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2),
                       "messageBlockByteCount cannot fit within a uint16_t\n");

    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_InitializeContextSHA512_224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_InitializeContextSHA512_256(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA384:
        {
            SHA2_InitializeContextSHA384(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA512:
        {
            SHA2_InitializeContextSHA512(&context);
            break;
        }
        default:
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid digest length for SHA512: %i", digestLength);
            sprintf(context.DigestStr, "");

            return context;
        }
    }

    while (*messagePtr != 0x00)
    {
        sha2_assert(messageBlockByteCount < SHA2_MESSAGE_BLOCK_SIZE_SHA512);
        uint128_t oldMessageLengthBits =
        {
            oldMessageLengthBits.High = context.MessageLengthBits.High,
            oldMessageLengthBits.Low = context.MessageLengthBits.Low,
        };

        messagePtr++;
        messageBlockByteCount++;
        IncrementUINT128(&context.MessageLengthBits, 8);
        if (UINT128GreaterThan(oldMessageLengthBits, context.MessageLengthBits))
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid message length: larger than 2^128 bits");
            sprintf(context.DigestStr, "");
            return context;
        }

        // Process the message in blocks of 1024 bits (128 bytes or sixteen 64-bit words)
        if (messageBlockByteCount == SHA2_MESSAGE_BLOCK_SIZE_SHA512)
        {
            SHA2_UpdateHashSHA512(&context, (uint8_t *)messagePtr - messageBlockByteCount, messageBlockByteCount);
            messageBlockByteCount = 0;
        }
    }

    // Allocate a buffer to store the final message block
    uint8_t buffer[SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2];
    uint16_t bufferSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2;
    sha2_static_assert(UINT16_MAX > (SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2),
                       "bufferSizeBytes cannot fit within a uint16_t\n");

#if HASHUTIL_SLOW
    // Note (Aaron): Useful for debug purposes to pack the buffer's bits with 1s
    SHA2_MemorySet(buffer, 0xff, bufferSizeBytes);
#endif

    // Copy message remainder (if any) into buffer
    if (messageBlockByteCount > 0)
    {
        SHA2_MemoryCopy(buffer, (uint8_t *)(messagePtr - messageBlockByteCount), messageBlockByteCount);
    }

    // Apply padding to the final message blocks(s)
    sha2_message_padding_info messageInfo =
    {
        messageInfo.BufferPtr = buffer,
        messageInfo.BufferSizeBytes = bufferSizeBytes,
        messageInfo.BlockSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA512,
        messageInfo.MessageRemainderSizeBytes = messageBlockByteCount,
        messageInfo.MessageLengthBlockSizeBytes = SHA2_MESSAGE_LENGTH_BLOCK_SHA512,
        messageInfo.MessageLengthBitsHigh = context.MessageLengthBits.High,
        messageInfo.MessageLengthBitsLow = context.MessageLengthBits.Low,
    };

    SHA2_ApplyPadding(messageInfo);

    // Apply final hash computation
    bool useFullBuffer = messageBlockByteCount > (SHA2_MESSAGE_BLOCK_SIZE_SHA512 - SHA2_MESSAGE_LENGTH_BLOCK_SHA512 - 1);
    messageBlockByteCount = useFullBuffer ? (bufferSizeBytes) : SHA2_MESSAGE_BLOCK_SIZE_SHA512;
    SHA2_UpdateHashSHA512(&context, (uint8_t *)buffer, messageBlockByteCount);

    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_ConstructDigestSHA512_224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_ConstructDigestSHA512_256(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA384:
        {
            SHA2_ConstructDigestSHA384(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA512:
        {
            SHA2_ConstructDigestSHA512(&context);
            break;
        }
        default:
        {
            // Invalid digest length for SHA512. We should never reach this state here.
            sha2_assert(false);
        }
    }

    return context;
}

sha2_512_context SHA2_HashFileSHA512_(char *fileName, sha2_digest_length digestLength)
{
    sha2_512_context context;
    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_InitializeContextSHA512_224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_InitializeContextSHA512_256(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA384:
        {
            SHA2_InitializeContextSHA384(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA512:
        {
            SHA2_InitializeContextSHA512(&context);
            break;
        }
        default:
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid digest length for SHA512: %i", digestLength);
            sprintf(context.DigestStr, "");
            return context;
        }
    }

    FILE *file = fopen(fileName, "rb");
    if (!file)
    {
        sha2_assert(false);

        context.Error = true;
        sprintf(context.ErrorStr, "Unable to open file");
        sprintf(context.DigestStr, "");
        return context;
    }

    // Note (Aaron): Create a buffer that can hold two full message blocks as
    // we will potentially use the extra space when applying padding later.
    uint8_t buffer[SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2];
    uint8_t *bufferPtr = buffer;
    uint16_t bufferSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2;
    sha2_static_assert(UINT16_MAX > (SHA2_MESSAGE_BLOCK_SIZE_SHA512 * 2),
                       "bufferSizeBytes cannot fit within a uint16_t\n");

#if HASHUTIL_SLOW
    SHA2_MemorySet(bufferPtr, 0xff, bufferSizeBytes);
#endif

    size_t readElementSize = sizeof(uint8_t);
    size_t readBlockSize = sizeof(uint8_t) * SHA2_MESSAGE_BLOCK_SIZE_SHA512;
    size_t blockBytesRead = 0;

    // Note (Aaron): Sanity check
    sha2_assert(readElementSize == 1);

    // Update hash using file contents until we run out of blocks of sufficient size
    blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
    while(blockBytesRead)
    {
        sha2_assert(blockBytesRead <= SHA2_MESSAGE_BLOCK_SIZE_SHA512);
        uint128_t oldMessageLengthBits =
        {
            oldMessageLengthBits.High = context.MessageLengthBits.High,
            oldMessageLengthBits.Low = context.MessageLengthBits.Low,
        };

        IncrementUINT128(&context.MessageLengthBits, (blockBytesRead * 8));
        if (UINT128GreaterThan(oldMessageLengthBits, context.MessageLengthBits))
        {
            sha2_assert(false);

            context.Error = true;
            sprintf(context.ErrorStr, "Invalid message length: larger than 2^128 bits");
            sprintf(context.DigestStr, "");
            return context;
        }

        if(blockBytesRead == SHA2_MESSAGE_BLOCK_SIZE_SHA512)
        {
            SHA2_UpdateHashSHA512(&context, bufferPtr, blockBytesRead);
            blockBytesRead = fread(buffer, readElementSize, readBlockSize, file);
            continue;
        }

        // Note (Aaron): If we ever read less bytes than SHA2_MESSAGE_LENGTH_BLOCK_SHA512,
        // it is time to stop reading the file and apply padding.
        break;
    }

    if (ferror(file))
    {
        fclose(file);
        sha2_assert(false);

        context.Error = true;
        sprintf(context.ErrorStr, "Error reading file");
        sprintf(context.DigestStr, "");
        return context;
    }

    fclose(file);

    // Apply the final hash update with padding
    sha2_message_padding_info messageInfo =
    {
        messageInfo.BufferPtr = buffer,
        messageInfo.BufferSizeBytes = bufferSizeBytes,
        messageInfo.BlockSizeBytes = SHA2_MESSAGE_BLOCK_SIZE_SHA512,
        messageInfo.MessageRemainderSizeBytes = blockBytesRead,
        messageInfo.MessageLengthBlockSizeBytes = SHA2_MESSAGE_LENGTH_BLOCK_SHA512,
        messageInfo.MessageLengthBitsHigh = context.MessageLengthBits.High,
        messageInfo.MessageLengthBitsLow = context.MessageLengthBits.Low,
    };

    SHA2_ApplyPadding(messageInfo);

    bool useFullBuffer = blockBytesRead > (SHA2_MESSAGE_BLOCK_SIZE_SHA512 - SHA2_MESSAGE_LENGTH_BLOCK_SHA512 - 1);
    blockBytesRead = useFullBuffer ? (bufferSizeBytes) : SHA2_MESSAGE_BLOCK_SIZE_SHA512;
    SHA2_UpdateHashSHA512(&context, buffer, blockBytesRead);

    switch (digestLength)
    {
        case SHA2_DIGEST_LENGTH_SHA224:
        {
            SHA2_ConstructDigestSHA512_224(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA256:
        {
            SHA2_ConstructDigestSHA512_256(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA384:
        {
            SHA2_ConstructDigestSHA384(&context);
            break;
        }
        case SHA2_DIGEST_LENGTH_SHA512:
        {
            SHA2_ConstructDigestSHA512(&context);
            break;
        }
        default:
        {
            // Invalid digest length for SHA512. We should never reach this state here.
            sha2_assert(false);
        }
    }

    return context;
}


sha2_256_context SHA2_HashStringSHA224(char *messagePtr)
{
    return SHA2_HashStringSHA256_(messagePtr, SHA2_DIGEST_LENGTH_SHA224);
}

sha2_256_context SHA2_HashStringSHA256(char *messagePtr)
{
    return SHA2_HashStringSHA256_(messagePtr, SHA2_DIGEST_LENGTH_SHA256);
}

sha2_256_context SHA2_HashFileSHA224(char *fileName)
{
    return SHA2_HashFileSHA256_(fileName, SHA2_DIGEST_LENGTH_SHA224);
}

sha2_256_context SHA2_HashFileSHA256(char *fileName)
{
    return SHA2_HashFileSHA256_(fileName, SHA2_DIGEST_LENGTH_SHA256);
}


sha2_512_context SHA2_HashStringSHA512_224(char *messagePtr)
{
    return SHA2_HashStringSHA512_(messagePtr, SHA2_DIGEST_LENGTH_SHA224);
}

sha2_512_context SHA2_HashStringSHA512_256(char *messagePtr)
{
    return SHA2_HashStringSHA512_(messagePtr, SHA2_DIGEST_LENGTH_SHA256);
}

sha2_512_context SHA2_HashStringSHA384(char *messagePtr)
{
    return SHA2_HashStringSHA512_(messagePtr, SHA2_DIGEST_LENGTH_SHA384);
}

sha2_512_context SHA2_HashStringSHA512(char *messagePtr)
{
    return SHA2_HashStringSHA512_(messagePtr, SHA2_DIGEST_LENGTH_SHA512);
}

sha2_512_context SHA2_HashFileSHA512_224(char *fileName)
{
    return SHA2_HashFileSHA512_(fileName, SHA2_DIGEST_LENGTH_SHA224);
}

sha2_512_context SHA2_HashFileSHA512_256(char *fileName)
{
    return SHA2_HashFileSHA512_(fileName, SHA2_DIGEST_LENGTH_SHA256);
}

sha2_512_context SHA2_HashFileSHA384(char *fileName)
{
    return SHA2_HashFileSHA512_(fileName, SHA2_DIGEST_LENGTH_SHA384);
}

sha2_512_context SHA2_HashFileSHA512(char *fileName)
{
    return SHA2_HashFileSHA512_(fileName, SHA2_DIGEST_LENGTH_SHA512);
}


#ifdef __cplusplus
}
#endif

#endif // HASHUTIL_SHA2_IMPLEMENTATION
