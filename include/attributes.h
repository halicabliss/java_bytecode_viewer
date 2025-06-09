#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#include <stdint.h>
#include <stdio.h>
#include "common.h"
#include "constant_pool.h"

// Structures for Specific Attributes
typedef struct {
    uint16_t constantvalue_index; // index into constant pool
} ConstantValue_attribute;

typedef struct {
    uint16_t start_pc;
    uint16_t end_pc;
    uint16_t handler_pc;
    uint16_t catch_type; // 0 or index to CONSTANT_Class_info
} exception_table_entry;

// forward declaration of the main attribute_info struct for recursive definition
typedef struct attribute_info attribute_info;

typedef struct {
    uint16_t max_stack;
    uint16_t max_locals;
    uint32_t code_length;
    uint8_t *code; // bytecode instructions
    uint16_t exception_table_length;
    exception_table_entry *exception_table;
    uint16_t attributes_count;
    attribute_info *attributes; // attributes of the code attribute
} Code_attribute;

typedef struct {
    uint8_t *entries;
    uint32_t length;
} StackMapTable_attribute;

typedef struct {
    uint16_t number_of_exceptions;
    uint16_t *exception_index_table; // array of indices to CONSTANT_Class_info
} Exceptions_attribute;

typedef struct {
    uint16_t inner_class_info_index;
    uint16_t outer_class_info_index;
    uint16_t inner_name_index;
    uint16_t inner_class_access_flags;
} classes_entry;

typedef struct {
    uint16_t number_of_classes;
    classes_entry *classes;
} InnerClasses_attribute;

typedef struct {
    uint16_t class_index; // intex to CONSTANT_Class_info
    uint16_t method_index; // index to CONSTANT_NameAndType_info (0 if not in a method)
} EnclosingMethod_attribute;


typedef struct {
    uint16_t signature_index; // index to CONSTANT_Utf8_info
} Signature_attribute;

typedef struct {
    uint16_t sourcefile_index; // index to CONSTANT_Utf8_info
} SourceFile_attribute;

typedef struct {
    uint8_t *debug_extension;
    uint32_t length;
} SourceDebugExtension_attribute;

typedef struct {
    uint16_t start_pc;
    uint16_t line_number;
} line_number_table_entry;

typedef struct {
    uint16_t line_number_table_length;
    line_number_table_entry *line_number_table;
} LineNumberTable_attribute;

typedef struct {
    uint16_t start_pc;
    uint16_t length;
    uint16_t name_index;        // index to CONSTANT_Utf8_info
    uint16_t descriptor_index;  // index to CONSTANT_Utf8_info
    uint16_t index;             // local variable slot index
} local_variable_table_entry;

typedef struct {
    uint16_t local_variable_table_length;
    local_variable_table_entry *local_variable_table;
} LocalVariableTable_attribute;

typedef struct {
    uint16_t start_pc;
    uint16_t length;
    uint16_t name_index;        // index to CONSTANT_Utf8_info
    uint16_t signature_index;   // index to CONSTANT_Utf8_info
    uint16_t index;             // local variable slot index
} local_variable_type_table_entry;

typedef struct {
    uint16_t local_variable_type_table_length;
    local_variable_type_table_entry *local_variable_type_table;
} LocalVariableTypeTable_attribute;


typedef struct {
    uint16_t num_annotations;
    uint8_t *raw_data;
    uint32_t raw_data_length; 
} Annotations_attribute_generic;

typedef struct {
    uint8_t *element_value;
    uint32_t length;
} AnnotationDefault_attribute;

typedef struct {
    uint16_t bootstrap_method_ref; // index to CONSTANT_MethodHandle_info
    uint16_t num_bootstrap_arguments;
    uint16_t *bootstrap_arguments; // array of indices into constant pool
} bootstrap_methods_entry;

typedef struct {
    uint16_t num_bootstrap_methods;
    bootstrap_methods_entry *bootstrap_methods;
} BootstrapMethods_attribute;

typedef struct {
    uint16_t name_index; // index to CONSTANT_Utf8_info
    uint16_t access_flags;
} parameters_entry;

typedef struct {
    uint8_t parameters_count;
    parameters_entry *parameters;
} MethodParameters_attribute;

typedef struct {
    uint16_t module_name_index;
    uint16_t module_flags;
    uint16_t module_version_index;
    uint16_t requires_count;
    uint16_t exports_count;
    uint16_t opens_count;
    uint16_t uses_count;
    uint16_t *uses_index_table; 
    uint16_t provides_count;
} Module_attribute;

typedef struct {
    uint16_t host_class_index; // index to CONSTANT_Class_info
} NestHost_attribute;

typedef struct {
    uint16_t number_of_members;
    uint16_t *classes_index_table; // array of indices to CONSTANT_Class_info
} NestMembers_attribute;

typedef struct {
    uint16_t number_of_classes;
    uint16_t *classes_index_table; // array of indices to CONSTANT_Class_info
} PermittedSubclasses_attribute;

typedef struct {
    uint16_t components_count;
} Record_attribute;



// this union holds the specific data for each attribute type
struct attribute_info {
    uint16_t attribute_name_index; // index into constant pool to a CONSTANT_Utf8_info
    uint32_t attribute_length;     // length of the info bytes following this header

    union {
        ConstantValue_attribute constant_value;
        Code_attribute code;
        StackMapTable_attribute stack_map_table;
        Exceptions_attribute exceptions;
        InnerClasses_attribute inner_classes;
        EnclosingMethod_attribute enclosing_method;
        Signature_attribute signature;
        SourceFile_attribute source_file;
        SourceDebugExtension_attribute source_debug_extension;
        LineNumberTable_attribute line_number_table;
        LocalVariableTable_attribute local_variable_table;
        LocalVariableTypeTable_attribute local_variable_type_table;
        Annotations_attribute_generic annotations_generic;
        AnnotationDefault_attribute annotation_default;
        BootstrapMethods_attribute bootstrap_methods;
        MethodParameters_attribute method_parameters;
        Module_attribute module;
        NestHost_attribute nest_host;
        NestMembers_attribute nest_members;
        PermittedSubclasses_attribute permitted_subclasses;
        Record_attribute record_attr;

        uint8_t *raw_bytes
    } info;
};

attribute_info* parse_attribute(FILE *fp, const cp_info *constant_pool);

void print_attribute(const attribute_info *attr, const cp_info *constant_pool);

void free_attribute(attribute_info *attr);

#endif 