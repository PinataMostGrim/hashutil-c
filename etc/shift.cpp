#include <stdio.h>
#include <stdint.h>

typedef uint8_t uint8;
typedef uint32_t uint32;


int main()
{
    // Reverse the order of the four byte blocks in 'x'
    uint32 x = 0b00001000000001000000001000000001;

    // Option 1
    {
        uint32 result = ((0b11111111000000000000000000000000 & x) >> 24)
            | ((0b00000000111111110000000000000000 & x) >> 8)
            | ((0b00000000000000001111111100000000 & x) << 8)
            | ((0b00000000000000000000000011111111 & x) << 24);
    }

    // Option 2
    {
        uint8 shifted[4] = {0};
        shifted[0] = uint8(x >> 24);
        shifted[1] = uint8(x >> 16);
        shifted[2] = uint8(x >> 8);
        shifted[3] = uint8(x >> 0);

        uint32 result = shifted[0] | (shifted[1] << 8) | (shifted[2] << 16) | (shifted[3] << 24);
    }

    // Option 3
    {
        uint32 result = (uint8(x >> 24)) | (uint8(x >> 16) << 8) | (uint8(x >> 8) << 16) | (uint8(x >> 0) << 24);
    }
}
