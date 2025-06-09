#ifndef FIELDS_H
#define FIELDS_H

#include <stdint.h>
#include <stdio.h> 
#include "common.h"
#include "attributes.h"


typedef struct {
    uint16_t access_flags;
    uint16_t name_index;
    uint16_t descriptor_index;
    uint16_t attributes_count;
    attribute_info *attributes;
} field_info;


field_info* parse_field_info(FILE *fp, const cp_info *constant_pool);


void print_field_info(const field_info *field, const cp_info *constant_pool);


void free_field_info(field_info *field);

#endif // FIELDS_H