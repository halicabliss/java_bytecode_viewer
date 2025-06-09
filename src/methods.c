#include "../include/methods.h"
#include "../include/constant_pool.h"
#include "../include/attributes.h"
#include "../include/common.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char* get_method_access_flags_string(uint16_t flags) {
    static char buffer[128];
    buffer[0] = '\0';

    if (flags & ACC_PUBLIC) strcat(buffer, "public ");
    if (flags & ACC_PRIVATE) strcat(buffer, "private ");
    if (flags & ACC_PROTECTED) strcat(buffer, "protected ");
    if (flags & ACC_STATIC) strcat(buffer, "static ");
    if (flags & ACC_FINAL) strcat(buffer, "final ");
    if (flags & ACC_SYNCHRONIZED) strcat(buffer, "synchronized ");
    if (flags & ACC_BRIDGE) strcat(buffer, "bridge ");
    if (flags & ACC_VARARGS) strcat(buffer, "varargs ");
    if (flags & ACC_NATIVE) strcat(buffer, "native ");
    if (flags & ACC_ABSTRACT) strcat(buffer, "abstract ");
    if (flags & ACC_STRICT) strcat(buffer, "strictfp ");
    if (flags & ACC_SYNTHETIC) strcat(buffer, "synthetic ");

    if (strlen(buffer) > 0) {
        buffer[strlen(buffer) - 1] = '\0';
    } else {
        strcat(buffer, "(no flags)");
    }
    return buffer;
}

// Parses a single method_info structure
method_info* parse_method_info(FILE *fp, const cp_info *constant_pool) {
    method_info *method = (method_info*) malloc(sizeof(method_info));
    if (!method) {
        perror("Failed to allocate memory for method_info");
        return NULL;
    }

    method->attributes = NULL;

    method->access_flags = read_u16(fp);
    method->name_index = read_u16(fp);
    method->descriptor_index = read_u16(fp);
    method->attributes_count = read_u16(fp);

    if (method->attributes_count > 0) {
        method->attributes = (attribute_info*) malloc(method->attributes_count * sizeof(attribute_info));
        if (!method->attributes) {
            perror("Failed to allocate memory for method attributes");
            free(method);
            return NULL;
        }

        for (int i = 0; i < method->attributes_count; ++i) {
            attribute_info *attr = parse_attribute(fp, constant_pool);
            if (!attr) {
                fprintf(stderr, "Error parsing attribute #%d for method.\n", i);
                for (int j = 0; j < i; ++j) {
                    free_attribute(&method->attributes[j]);
                }
                free(method->attributes);
                free(method);
                return NULL;
            }
            memcpy(&method->attributes[i], attr, sizeof(attribute_info));
            free(attr);
        }
    } else {
        method->attributes = NULL;
    }

    return method;
}

// Prints the contents of a single method_info structure
void print_method_info(const method_info *method, const cp_info *constant_pool) {
    if (!method) return;

    const char* name = get_utf8_string(constant_pool, method->name_index);
    const char* descriptor = get_utf8_string(constant_pool, method->descriptor_index);

    printf("  Access Flags: 0x%04X (%s)\n", method->access_flags, get_method_access_flags_string(method->access_flags));
    printf("  Name: #%u // %s\n", method->name_index, name);
    printf("  Descriptor: #%u // %s\n", method->descriptor_index, descriptor);
    printf("  Attributes Count: %u\n", method->attributes_count);

    if (method->attributes_count > 0) {
        printf("  Attributes:\n");
        for (int i = 0; i < method->attributes_count; ++i) {
            printf("    [%d] ", i);
            print_attribute(&method->attributes[i], constant_pool);
        }
    }
}

// Frees memory allocated for a single method_info structure
void free_method_info(method_info *method) {
    if (method) {
        if (method->attributes) {
            for (int i = 0; i < method->attributes_count; ++i) {
                free_attribute(&method->attributes[i]);
            }
            free(method->attributes);
            method->attributes = NULL;
        }
        free(method);
    }
}