#include "../include/common.h"
#include <stdlib.h>
#include <stdio.h>

// Reads a 16-bit unsigned integer from the file 
uint16_t read_u16(FILE *fp) {
    uint16_t val;
    if (fread(&val, sizeof(uint16_t), 1, fp) != 1) {
        exit(EXIT_FAILURE);
    }

    // Big-endian -> little-endian conversion
    return SWAP_U16(val);
}

// Reads a 32-bit unsigned integer from the file
uint32_t read_u32(FILE *fp) {
    uint32_t val;
    if (fread(&val, sizeof(uint32_t), 1, fp) != 1) {
        exit(EXIT_FAILURE);
    }

    // Big-endian -> little-endian conversion
    return SWAP_U32(val);
}