#ifndef CLASS_FILE_H
#define CLASS_FILE_H

#include <stdint.h>
#include <stdio.h>
#include "common.h"
#include "constant_pool.h"
#include "attributes.h"

#include "fields.h"
#include "methods.h"


typedef struct {
    uint32_t magic;
    uint16_t minor_version;
    uint16_t major_version;
    uint16_t constant_pool_count;
    cp_info *constant_pool;
    uint16_t access_flags;
    uint16_t this_class;
    uint16_t super_class;
    uint16_t interfaces_count;
    uint16_t *interfaces;

    uint16_t fields_count;
    field_info *fields;

    uint16_t methods_count;
    method_info *methods;

    uint16_t attributes_count;
    attribute_info *attributes;
} ClassFile;

ClassFile* parse_class_file(const char *filepath);

void print_class_file_info(const ClassFile *cf);

void free_class_file(ClassFile *cf);

#endif