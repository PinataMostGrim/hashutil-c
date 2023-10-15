#ifndef SUPPORTED_HASHES_H
#define SUPPORTED_HASHES_H


typedef enum hash_algorithm
{
    hash_unknown,
    hash_md5,
    hash_sha1,
    hash_sha224,
    hash_sha256,
    hash_sha384,
    hash_sha512,
    hash_sha512_224,
    hash_sha512_256,

    hash_algorithm_count,

} hash_algorithm;


static const char *HashAlgorithmMnemonics[] =
{
    "unknown",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
};


static hash_algorithm GetHashAlgorithm(char *algorithmPtr);
static const char *GetHashMenemonic(hash_algorithm algorithm);

#endif // SUPPORTED_HASHES_H
