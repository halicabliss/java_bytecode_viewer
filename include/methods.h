#ifndef METHODS_H
#define METHODS_H

#include <stdint.h>
#include <stdio.h>
#include "common.h"
#include "attributes.h" 

typedef struct {
    uint16_t access_flags;
    uint16_t name_index;        // Index into constant pool to a CONSTANT_Utf8_info (method name)
    uint16_t descriptor_index;  // Index into constant pool to a CONSTANT_Utf8_info (method signature)
    uint16_t attributes_count;
    attribute_info *attributes; // Array of attributes for this method (e.g., Code, Exceptions, Synthetic)
} method_info;



method_info* parse_method_info(FILE *fp, const cp_info *constant_pool);

void print_method_info(const method_info *method, const cp_info *constant_pool);

void free_method_info(method_info *method);

#endif // METHODS_H