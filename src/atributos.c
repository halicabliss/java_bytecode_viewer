#include "attributes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ==================================================
// **Função Auxiliar: Ler bytes do arquivo .class**
// ==================================================
static uint16_t read_u16(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}

static uint32_t read_u32(const uint8_t* data) {
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

// ==================================================
// **parse_attribute() - Factory de Atributos**
// ==================================================
JavaAttribute* parse_attribute(uint8_t* data, const uint16_t* constant_pool) {
    uint16_t name_index = read_u16(data);
    data += 2;
    uint32_t length = read_u32(data);
    data += 4;

    // Determinar o tipo do atributo (simplificado)
    const char* attr_name = (const char*)constant_pool[name_index - 1]; // Assume que constant_pool contém strings
    JavaAttributeType type = ATTRIBUTE_Custom;

    if (strcmp(attr_name, "ConstantValue") == 0) type = ATTRIBUTE_ConstantValue;
    else if (strcmp(attr_name, "Code") == 0) type = ATTRIBUTE_Code;
    // ... (mais comparações para outros atributos)

    // Alocar e preencher a struct correta
    switch (type) {
        case ATTRIBUTE_ConstantValue: {
            ConstantValueAttribute* attr = malloc(sizeof(ConstantValueAttribute));
            attr->base.type = type;
            attr->base.attribute_name_index = name_index;
            attr->base.attribute_length = length;
            attr->constantvalue_index = read_u16(data);
            return (JavaAttribute*)attr;
        }

        case ATTRIBUTE_Code: {
            CodeAttribute* attr = malloc(sizeof(CodeAttribute));
            attr->base.type = type;
            attr->base.attribute_name_index = name_index;
            attr->base.attribute_length = length;
            
            attr->max_stack = read_u16(data); data += 2;
            attr->max_locals = read_u16(data); data += 2;
            attr->code_length = read_u32(data); data += 4;
            attr->code = malloc(attr->code_length);
            memcpy(attr->code, data, attr->code_length); data += attr->code_length;
            
            attr->exception_table_length = read_u16(data); data += 2;
            attr->exception_table = malloc(attr->exception_table_length * sizeof(*attr->exception_table));
            for (int i = 0; i < attr->exception_table_length; i++) {
                attr->exception_table[i].start_pc = read_u16(data); data += 2;
                attr->exception_table[i].end_pc = read_u16(data); data += 2;
                attr->exception_table[i].handler_pc = read_u16(data); data += 2;
                attr->exception_table[i].catch_type = read_u16(data); data += 2;
            }
            
            attr->attributes_count = read_u16(data); data += 2;
            attr->attributes = malloc(attr->attributes_count * sizeof(JavaAttribute*));
            for (int i = 0; i < attr->attributes_count; i++) {
                attr->attributes[i] = parse_attribute(data, constant_pool);
                data += attr->attributes[i]->attribute_length + 6; // +6 para name_index e length
            }
            
            return (JavaAttribute*)attr;
        }

        // ... (implementar outros casos)

        default: {
            // Atributo desconhecido (tratar como raw data)
            JavaAttribute* attr = malloc(sizeof(JavaAttribute));
            attr->type = type;
            attr->attribute_name_index = name_index;
            attr->attribute_length = length;
            return attr;
        }
    }
}

// ==================================================
// **print_attribute() - Debug de Atributos**
// ==================================================
void print_attribute(JavaAttribute* attr) {
    switch (attr->type) {
        case ATTRIBUTE_ConstantValue:
            printf("[ConstantValue] constantvalue_index=%u\n", 
                   ((ConstantValueAttribute*)attr)->constantvalue_index);
            break;

        case ATTRIBUTE_Code: {
            CodeAttribute* code = (CodeAttribute*)attr;
            printf("[Code] max_stack=%u, max_locals=%u, code_length=%u\n",
                   code->max_stack, code->max_locals, code->code_length);
            // Imprimir sub-atributos recursivamente
            for (int i = 0; i < code->attributes_count; i++) {
                print_attribute(code->attributes[i]);
            }
            break;
        }

        // ... (implementar outros casos)

        default:
            printf("[Unknown Attribute] type=%d, length=%u\n", attr->type, attr->attribute_length);
    }
}

// ==================================================
// **free_attribute() - Liberar Memória**
// ==================================================
void free_attribute(JavaAttribute* attr) {
    switch (attr->type) {
        case ATTRIBUTE_Code: {
            CodeAttribute* code = (CodeAttribute*)attr;
            free(code->code);
            free(code->exception_table);
            for (int i = 0; i < code->attributes_count; i++) {
                free_attribute(code->attributes[i]);
            }
            free(code->attributes);
            break;
        }
        // ... (outros casos)
    }
    free(attr);
}
