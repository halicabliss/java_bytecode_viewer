#ifndef CONSTANT_POOL_H
#define CONSTANT_POOL_H

#include <stdint.h>
#include <stdio.h> 
#include "common.h" // for read_u16 and read_u32

// Constant pool tags
typedef enum {
    CONSTANT_Invalid = 0,
    CONSTANT_Utf8 = 1,
    CONSTANT_Integer = 3,
    CONSTANT_Float = 4,
    CONSTANT_Long = 5,
    CONSTANT_Double = 6,
    CONSTANT_Class = 7,
    CONSTANT_String = 8,
    CONSTANT_Fieldref = 9,
    CONSTANT_Methodref = 10,
    CONSTANT_InterfaceMethodref = 11,
    CONSTANT_NameAndType = 12,
    CONSTANT_MethodHandle = 15,
    CONSTANT_MethodType = 16,
    CONSTANT_Dynamic = 17,
    CONSTANT_InvokeDynamic = 18,
    CONSTANT_Module = 19,
    CONSTANT_Package = 20
} constant_pool_tag;

// Structs for constant pool entries
typedef struct {
    uint16_t length;
    uint8_t *bytes; // null-terminated string
} CONSTANT_Utf8_info;

// etc ...

// Union will hold the constant pool entry based on its tag
typedef struct {
    uint8_t tag;
    union {
        CONSTANT_Utf8_info utf8_info;
        // struct { uint32_t bytes; } integer_info;
        // struct { uint16_t name_index; } class_info;
        // etc ...
    } info;
} cp_info;

// Function to parse a single constant pool entry
cp_info* parse_constant_pool_entry(FILE *fp);

// Function to print a constant pool entry
void print_constant_pool_entry(const cp_info *entry, int index);

// Function to free constant pool memory
void free_constant_pool(cp_info *constant_pool, uint16_t count);

// Function to resolve a UTF-8 string from the constant pool
const char* get_utf8_string(const cp_info *constant_pool, uint16_t index);


#endif