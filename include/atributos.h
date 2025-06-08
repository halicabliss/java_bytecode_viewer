#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#include <stdint.h>

// ==================================================
// **Enumeração de TODOS os atributos do Java 8**
// ==================================================
typedef enum {
    ATTRIBUTE_ConstantValue,
    ATTRIBUTE_Code,
    ATTRIBUTE_StackMapTable,
    ATTRIBUTE_Exceptions,
    ATTRIBUTE_InnerClasses,
    ATTRIBUTE_EnclosingMethod,
    ATTRIBUTE_Synthetic,
    ATTRIBUTE_Signature,
    ATTRIBUTE_SourceFile,
    ATTRIBUTE_SourceDebugExtension,
    ATTRIBUTE_LineNumberTable,
    ATTRIBUTE_LocalVariableTable,
    ATTRIBUTE_LocalVariableTypeTable,
    ATTRIBUTE_Deprecated,
    ATTRIBUTE_RuntimeVisibleAnnotations,
    ATTRIBUTE_RuntimeInvisibleAnnotations,
    ATTRIBUTE_RuntimeVisibleParameterAnnotations,
    ATTRIBUTE_RuntimeInvisibleParameterAnnotations,
    ATTRIBUTE_RuntimeVisibleTypeAnnotations,
    ATTRIBUTE_RuntimeInvisibleTypeAnnotations,
    ATTRIBUTE_AnnotationDefault,
    ATTRIBUTE_BootstrapMethods,
    ATTRIBUTE_MethodParameters,
    ATTRIBUTE_Custom
} JavaAttributeType;

// ==================================================
// **Struct Base (comum a todos)**
// ==================================================
typedef struct {
    JavaAttributeType type;
    uint16_t attribute_name_index;  // Índice na Constant Pool
    uint32_t attribute_length;      // Tamanho em bytes
} JavaAttribute;

// ==================================================
// **Structs Específicas para Cada Atributo**
// ==================================================

// 1. ConstantValue (4.7.2)
typedef struct {
    JavaAttribute base;
    uint16_t constantvalue_index;  // Índice na Constant Pool
} ConstantValueAttribute;

// 2. Code (4.7.3)
typedef struct {
    JavaAttribute base;
    uint16_t max_stack;
    uint16_t max_locals;
    uint32_t code_length;
    uint8_t* code;                  // Bytecode
    uint16_t exception_table_length;
    struct {
        uint16_t start_pc;
        uint16_t end_pc;
        uint16_t handler_pc;
        uint16_t catch_type;
    }* exception_table;
    uint16_t attributes_count;
    JavaAttribute** attributes;      // Sub-atributos (LineNumberTable, etc.)
} CodeAttribute;

// 3. StackMapTable (4.7.4)
typedef struct {
    JavaAttribute base;
    uint16_t number_of_entries;
    uint8_t* entries;               // Array de stack_map_frame
} StackMapTableAttribute;

// 4. Exceptions (4.7.5)
typedef struct {
    JavaAttribute base;
    uint16_t number_of_exceptions;
    uint16_t* exception_index_table; // Índices de Class_info
} ExceptionsAttribute;

// 5. InnerClasses (4.7.6)
typedef struct {
    JavaAttribute base;
    uint16_t number_of_classes;
    struct {
        uint16_t inner_class_info_index;
        uint16_t outer_class_info_index;
        uint16_t inner_name_index;
        uint16_t inner_class_access_flags;
    }* classes;
} InnerClassesAttribute;

// 6. EnclosingMethod (4.7.7)
typedef struct {
    JavaAttribute base;
    uint16_t class_index;
    uint16_t method_index;
} EnclosingMethodAttribute;

// 7. Synthetic (4.7.8) - Sem campos adicionais
typedef JavaAttribute SyntheticAttribute;

// 8. Signature (4.7.9)
typedef struct {
    JavaAttribute base;
    uint16_t signature_index;        // Índice de CONSTANT_Utf8
} SignatureAttribute;

// 9. SourceFile (4.7.10)
typedef struct {
    JavaAttribute base;
    uint16_t sourcefile_index;       // Índice de CONSTANT_Utf8
} SourceFileAttribute;

// 10. SourceDebugExtension (4.7.11)
typedef struct {
    JavaAttribute base;
    uint8_t* debug_extension;        // Dados brutos
} SourceDebugExtensionAttribute;

// 11. LineNumberTable (4.7.12)
typedef struct {
    JavaAttribute base;
    uint16_t line_number_table_length;
    struct {
        uint16_t start_pc;
        uint16_t line_number;
    }* line_number_table;
} LineNumberTableAttribute;

// 12. LocalVariableTable (4.7.13)
typedef struct {
    JavaAttribute base;
    uint16_t local_variable_table_length;
    struct {
        uint16_t start_pc;
        uint16_t length;
        uint16_t name_index;
        uint16_t descriptor_index;
        uint16_t index;
    }* local_variable_table;
} LocalVariableTableAttribute;

// 13. LocalVariableTypeTable (4.7.14)
typedef struct {
    JavaAttribute base;
    uint16_t local_variable_type_table_length;
    struct {
        uint16_t start_pc;
        uint16_t length;
        uint16_t name_index;
        uint16_t signature_index;
        uint16_t index;
    }* local_variable_type_table;
} LocalVariableTypeTableAttribute;

// 14. Deprecated (4.7.15) - Sem campos adicionais
typedef JavaAttribute DeprecatedAttribute;

// 15. RuntimeVisibleAnnotations (4.7.16)
typedef struct {
    JavaAttribute base;
    uint16_t num_annotations;
    uint8_t* annotations_data;       // Estrutura complexa de anotações
} RuntimeVisibleAnnotationsAttribute;

// 16. RuntimeInvisibleAnnotations (4.7.17)
typedef RuntimeVisibleAnnotationsAttribute RuntimeInvisibleAnnotationsAttribute;

// 17. RuntimeVisibleParameterAnnotations (4.7.18)
typedef struct {
    JavaAttribute base;
    uint8_t num_parameters;
    struct {
        uint16_t num_annotations;
        uint8_t* annotations_data;
    }* parameter_annotations;
} RuntimeVisibleParameterAnnotationsAttribute;

// 18. RuntimeInvisibleParameterAnnotations (4.7.19)
typedef RuntimeVisibleParameterAnnotationsAttribute RuntimeInvisibleParameterAnnotationsAttribute;

// 19. RuntimeVisibleTypeAnnotations (4.7.20)
typedef struct {
    JavaAttribute base;
    uint16_t num_annotations;
    uint8_t* annotations_data;       // Type annotations extendidas
} RuntimeVisibleTypeAnnotationsAttribute;

// 20. RuntimeInvisibleTypeAnnotations (4.7.21)
typedef RuntimeVisibleTypeAnnotationsAttribute RuntimeInvisibleTypeAnnotationsAttribute;

// 21. AnnotationDefault (4.7.22)
typedef struct {
    JavaAttribute base;
    uint8_t* default_value;          // ElementValue
} AnnotationDefaultAttribute;

// 22. BootstrapMethods (4.7.23)
typedef struct {
    JavaAttribute base;
    uint16_t num_bootstrap_methods;
    struct {
        uint16_t bootstrap_method_ref;
        uint16_t num_bootstrap_arguments;
        uint16_t* bootstrap_arguments;
    }* bootstrap_methods;
} BootstrapMethodsAttribute;

// 23. MethodParameters (4.7.24)
typedef struct {
    JavaAttribute base;
    uint8_t parameters_count;
    struct {
        uint16_t name_index;
        uint16_t access_flags;
    }* parameters;
} MethodParametersAttribute;

// ==================================================
// **Funções para Manipulação**
// ==================================================
JavaAttribute* parse_attribute(uint8_t* data, const uint16_t* constant_pool);
void free_attribute(JavaAttribute* attr);

#endif // ATTRIBUTES_H
