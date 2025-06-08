#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

// Lista de atributos padrão do Java 8 (como constantes)
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
    // Atributos customizados (exemplo)
    ATTRIBUTE_KotlinMetadata,
    ATTRIBUTE_LombokGenerated
} JavaAttributeType;

// Estrutura para representar um atributo genérico
typedef struct {
    JavaAttributeType type;
    const char* name;
    uint32_t length;
    uint8_t* info; // Dados brutos do atributo
} JavaAttribute;

#endif // ATTRIBUTES_H
