#ifndef CLASS_FILE_H
#define CLASS_FILE_H

#include <stdint.h>
#include <stdio.h>
#include "constant_pool.h" // for cp_info

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
    uint16_t *interfaces; // Array of interface indices
    uint16_t fields_count;
    // field_info *fields; // Placeholder for field structures
    uint16_t methods_count;
    // method_info *methods; // Placeholder for method structures
    uint16_t attributes_count;
    // attribute_info *attributes; // Placeholder for class attributes
} ClassFile;

// Function to parse the entire ClassFile
ClassFile* parse_class_file(const char *filepath);

// Function to print ClassFile general info
void print_class_file_info(const ClassFile *cf);

// Function to free ClassFile memory
void free_class_file(ClassFile *cf);

#endif