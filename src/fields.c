#include "../include/fields.h"
#include "../include/common.h"
#include "../include/constant_pool.h"
#include "../include/attributes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


static const char* get_field_access_flags_string(uint16_t flags) {
    static char buffer[128];
    buffer[0] = '\0';

    if (flags & ACC_PUBLIC)    strcat(buffer, "public ");
    if (flags & ACC_PRIVATE)   strcat(buffer, "private ");
    if (flags & ACC_PROTECTED) strcat(buffer, "protected ");
    if (flags & ACC_STATIC)    strcat(buffer, "static ");
    if (flags & ACC_FINAL)     strcat(buffer, "final ");
    if (flags & ACC_VOLATILE)  strcat(buffer, "volatile ");
    if (flags & ACC_TRANSIENT) strcat(buffer, "transient ");
    if (flags & ACC_SYNTHETIC) strcat(buffer, "synthetic ");
    if (flags & ACC_ENUM)      strcat(buffer, "enum ");

    if (strlen(buffer) > 0) {
        buffer[strlen(buffer) - 1] = '\0';
    } else {
        strcat(buffer, " (no flags)");
    }
    return buffer;
}



field_info* parse_field_info(FILE *fp, const cp_info *constant_pool) {
    field_info *field = (field_info*) malloc(sizeof(field_info));
    if (!field) {
        perror("Failed to allocate memory for field_info");
        return NULL;
    }

    field->access_flags = read_u16(fp);
    field->name_index = read_u16(fp);
    field->descriptor_index = read_u16(fp);
    field->attributes_count = read_u16(fp);

    field->attributes = NULL;

    if (field->attributes_count > 0) {
        field->attributes = (attribute_info*) malloc(field->attributes_count * sizeof(attribute_info));
        if (!field->attributes) {
            perror("Failed to allocate memory for field attributes");
            free(field);
            return NULL;
        }

        for (int i = 0; i < field->attributes_count; ++i) {
            attribute_info *attr = parse_attribute(fp, constant_pool);
            if (!attr) {
                fprintf(stderr, "Error parsing attribute for field.\n");
                for (int j = 0; j < i; ++j) {
                    free_attribute(&field->attributes[j]);
                }
                free(field->attributes);
                free(field);
                return NULL;
            }
            memcpy(&field->attributes[i], attr, sizeof(attribute_info));
            free(attr);
        }
    }

    return field;
}

void print_field_info(const field_info *field, const cp_info *constant_pool) {
    if (!field) return;

    const char* field_name = get_utf8_string(constant_pool, field->name_index);
    const char* field_descriptor = get_utf8_string(constant_pool, field->descriptor_index);
    const char* flags_str = get_field_access_flags_string(field->access_flags);

    printf("  Field: %s %s %s (flags: 0x%04X)\n",
           flags_str, field_descriptor, field_name, field->access_flags);
    printf("    Name Index: #%u\n", field->name_index);
    printf("    Descriptor Index: #%u\n", field->descriptor_index);
    printf("    Attributes Count: %u\n", field->attributes_count);

    if (field->attributes_count > 0) {
        printf("    Field Attributes:\n");
        for (int i = 0; i < field->attributes_count; ++i) {
            printf("      [%d] ", i);
            print_attribute(&field->attributes[i], constant_pool);
        }
    }
}

void free_field_info(field_info *field) {
    if (field) {
        if (field->attributes) {
            for (int i = 0; i < field->attributes_count; ++i) {
                free_attribute(&field->attributes[i]);
            }
            free(field->attributes);
        }
        free(field);
    }
}