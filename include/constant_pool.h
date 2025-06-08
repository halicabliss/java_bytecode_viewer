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

typedef struct {
    uint32_t bytes; // int value
} CONSTANT_Integer_info;

typedef struct {
    uint32_t bytes; // float value in IEEE 754 format
} CONSTANT_Float_info;

typedef struct {
    uint32_t high_bytes;
    uint32_t low_bytes; 
} CONSTANT_Long_info;

typedef struct {
    uint32_t high_bytes;
    uint32_t low_bytes;
} CONSTANT_Double_info;

typedef struct {
    uint16_t name_index; // index -> CONSTANT_Utf8_info
} CONSTANT_Class_info;

typedef struct {
    uint16_t string_index; // index -> CONSTANT_Utf8_info
} CONSTANT_String_info;

typedef struct {
    uint16_t class_index;
    uint16_t name_and_type_index;
} CONSTANT_Fieldref_info;

typedef struct {
    uint16_t class_index;
    uint16_t name_and_type_index;
} CONSTANT_Methodref_info;

typedef struct {
    uint16_t class_index;
    uint16_t name_and_type_index;
} CONSTANT_InterfaceMethodref_info;

typedef struct {
    uint16_t name_index;            // index -> CONSTANT_Utf8_info
    uint16_t descriptor_index;      // index -> CONSTANT_Utf8_info
} CONSTANT_NameAndType_info;

typedef struct {
    uint8_t reference_kind;         // Indicates the kind of method handle
    uint16_t reference_index;       // Index into the constant pool to a CONSTANT_Fieldref_info,
                                    // CONSTANT_Methodref_info, or CONSTANT_InterfaceMethodref_info,
                                    // or CONSTANT_MethodHandle_info itself, depending on reference_kind
} CONSTANT_MethodHandle_info;

typedef struct {
    uint16_t descriptor_index;
} CONSTANT_MethodType_info;

typedef struct {
    uint16_t bootstrap_method_attr_index;
    uint16_t name_and_type_index;
} CONSTANT_Dynamic_info;

typedef struct {
    uint16_t bootstrap_method_attr_index;
    uint16_t name_and_type_index;
}  CONSTANT_InvokeDynamic_info;

typedef struct {
    uint16_t name_index;
} CONSTANT_Module_info;

typedef struct {
    uint16_t name_index;
} CONSTANT_Package_info;


// Union will hold the constant pool entry based on its tag
typedef struct {
    uint8_t tag;
    union {
        CONSTANT_Utf8_info utf8_info;
        CONSTANT_Integer_info integer_info;
        CONSTANT_Float_info float_info;
        CONSTANT_Long_info long_info;
        CONSTANT_Double_info double_info;
        CONSTANT_Class_info class_info;
        CONSTANT_String_info string_info;
        CONSTANT_Fieldref_info fieldref_info;
        CONSTANT_Methodref_info methodref_info;
        CONSTANT_InterfaceMethodref_info interface_methodref_info;
        CONSTANT_NameAndType_info name_and_type_info;
        CONSTANT_MethodHandle_info method_handle_info;
        CONSTANT_MethodType_info method_type_info;
        CONSTANT_Dynamic_info dynamic_info;
        CONSTANT_InvokeDynamic_info invoke_dynamic_info;
        CONSTANT_Module_info module_info;
        CONSTANT_Package_info package_info;
    } info;
} cp_info;

cp_info* parse_constant_pool_entry(FILE *fp);

void print_constant_pool_entry(const cp_info *entry, int index, const cp_info *full_constant_pool);

void free_constant_pool(cp_info *constant_pool, uint16_t count);

const char* get_utf8_string(const cp_info *constant_pool, uint16_t index);

#endif