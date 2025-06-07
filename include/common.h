#ifndef COMMON_H
#define COMMON_H

#include <stdint.h> 
#include <stdio.h> 

// Swap big endian <-> little endian
#define SWAP_U16(x) (((x) >> 8) | ((x) << 8))
#define SWAP_U32(x) ((((x) & 0xFF000000) >> 24) | \
                     (((x) & 0x00FF0000) >> 8)  | \
                     (((x) & 0x0000FF00) << 8)  | \
                     (((x) & 0x000000FF) << 24))


uint16_t read_u16(FILE *fp);

uint32_t read_u32(FILE *fp);

#endif