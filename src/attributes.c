#include "../include/attributes.h"
#include "../include/common.h"
#include "../include/constant_pool.h"
#include "../include/bytecode_disassembler.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


static void skip_attribute_bytes(FILE *fp, uint32_t length) {
    if (fseek(fp, length, SEEK_CUR) != 0) {
        perror("Error skipping attribute bytes");
    }
}

static void free_raw_bytes_if_present(attribute_info *attr) {
    if (attr->info.raw_bytes != NULL) {
        free(attr->info.raw_bytes);
        attr->info.raw_bytes = NULL;
    }
}


// Parses a single attribute from the file stream.
// Requires the full constant pool to resolve attribute names.
attribute_info* parse_attribute(FILE *fp, const cp_info *constant_pool) {
    attribute_info *attr = (attribute_info*) malloc(sizeof(attribute_info));
    if (!attr) {
        perror("Failed to allocate memory for attribute_info");
        return NULL;
    }

    attr->attribute_name_index = read_u16(fp);
    attr->attribute_length = read_u32(fp);

    // Get the attribute name string from the constant pool
    const char *attr_name = get_utf8_string(constant_pool, attr->attribute_name_index);

    // Initialize raw_bytes to NULL as a safety measure
    attr->info.raw_bytes = NULL;

    // Parsing Logic based on Attribute Name
    if (strcmp(attr_name, "ConstantValue") == 0) {
        attr->info.constant_value.constantvalue_index = read_u16(fp);
    } else if (strcmp(attr_name, "Code") == 0) {
        attr->info.code.max_stack = read_u16(fp);
        attr->info.code.max_locals = read_u16(fp);
        attr->info.code.code_length = read_u32(fp);

        attr->info.code.code = (uint8_t*) malloc(attr->info.code.code_length * sizeof(uint8_t));
        if (!attr->info.code.code) {
            perror("Failed to allocate memory for code bytes");
            free(attr);
            return NULL;
        }
        if (fread(attr->info.code.code, sizeof(uint8_t), attr->info.code.code_length, fp) != attr->info.code.code_length) {
            perror("Error reading code bytes");
            free(attr->info.code.code);
            free(attr);
            return NULL;
        }

        attr->info.code.exception_table_length = read_u16(fp);
        attr->info.code.exception_table = NULL;
        if (attr->info.code.exception_table_length > 0) {
            attr->info.code.exception_table = (exception_table_entry*) malloc(attr->info.code.exception_table_length * sizeof(exception_table_entry));
            if (!attr->info.code.exception_table) {
                perror("Failed to allocate memory for exception table");
                free(attr->info.code.code);
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.code.exception_table_length; ++i) {
                attr->info.code.exception_table[i].start_pc = read_u16(fp);
                attr->info.code.exception_table[i].end_pc = read_u16(fp);
                attr->info.code.exception_table[i].handler_pc = read_u16(fp);
                attr->info.code.exception_table[i].catch_type = read_u16(fp);
            }
        }

        attr->info.code.attributes_count = read_u16(fp);
        attr->info.code.attributes = NULL; // Initialize
        if (attr->info.code.attributes_count > 0) {
            attr->info.code.attributes = (attribute_info*) malloc(attr->info.code.attributes_count * sizeof(attribute_info));
            if (!attr->info.code.attributes) {
                perror("Failed to allocate memory for code sub-attributes");
                if (attr->info.code.exception_table) free(attr->info.code.exception_table);
                if (attr->info.code.code) free(attr->info.code.code);
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.code.attributes_count; ++i) {
                attribute_info *sub_attr = parse_attribute(fp, constant_pool);
                if (!sub_attr) {
                    fprintf(stderr, "Error parsing sub-attribute for Code attribute.\n");
                    for (int j = 0; j < i; ++j) {
                        free_attribute(&attr->info.code.attributes[j]);
                    }
                    free(attr->info.code.attributes);
                    if (attr->info.code.exception_table) free(attr->info.code.exception_table);
                    if (attr->info.code.code) free(attr->info.code.code);
                    free(attr);
                    return NULL;
                }
                memcpy(&attr->info.code.attributes[i], sub_attr, sizeof(attribute_info));
                free(sub_attr);
            }
        }
    } else if (strcmp(attr_name, "StackMapTable") == 0) {
        attr->info.stack_map_table.length = attr->attribute_length; // store the original length
        attr->info.stack_map_table.entries = (uint8_t*) malloc(attr->attribute_length * sizeof(uint8_t));
        if (!attr->info.stack_map_table.entries) {
            perror("Failed to allocate memory for StackMapTable entries");
            free(attr);
            return NULL;
        }
        if (fread(attr->info.stack_map_table.entries, sizeof(uint8_t), attr->attribute_length, fp) != attr->attribute_length) {
            perror("Error reading StackMapTable entries");
            free(attr->info.stack_map_table.entries);
            free(attr);
            return NULL;
        }
    } else if (strcmp(attr_name, "Exceptions") == 0) {
        attr->info.exceptions.number_of_exceptions = read_u16(fp);
        attr->info.exceptions.exception_index_table = NULL;
        if (attr->info.exceptions.number_of_exceptions > 0) {
            attr->info.exceptions.exception_index_table = (uint16_t*) malloc(attr->info.exceptions.number_of_exceptions * sizeof(uint16_t));
            if (!attr->info.exceptions.exception_index_table) {
                perror("Failed to allocate memory for exception index table");
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.exceptions.number_of_exceptions; ++i) {
                attr->info.exceptions.exception_index_table[i] = read_u16(fp);
            }
        }
    } else if (strcmp(attr_name, "InnerClasses") == 0) {
        attr->info.inner_classes.number_of_classes = read_u16(fp);
        attr->info.inner_classes.classes = NULL;
        if (attr->info.inner_classes.number_of_classes > 0) {
            attr->info.inner_classes.classes = (classes_entry*) malloc(attr->info.inner_classes.number_of_classes * sizeof(classes_entry));
            if (!attr->info.inner_classes.classes) {
                perror("Failed to allocate memory for inner classes entries");
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.inner_classes.number_of_classes; ++i) {
                attr->info.inner_classes.classes[i].inner_class_info_index = read_u16(fp);
                attr->info.inner_classes.classes[i].outer_class_info_index = read_u16(fp);
                attr->info.inner_classes.classes[i].inner_name_index = read_u16(fp);
                attr->info.inner_classes.classes[i].inner_class_access_flags = read_u16(fp);
            }
        }
    } else if (strcmp(attr_name, "EnclosingMethod") == 0) {
        attr->info.enclosing_method.class_index = read_u16(fp);
        attr->info.enclosing_method.method_index = read_u16(fp);
    } else if (strcmp(attr_name, "Synthetic") == 0 || strcmp(attr_name, "Deprecated") == 0) {
        if (attr->attribute_length != 0) {
            fprintf(stderr, "Warning: %s attribute has unexpected length %u.\n", attr_name, attr->attribute_length);
            skip_attribute_bytes(fp, attr->attribute_length);
        }
    } else if (strcmp(attr_name, "Signature") == 0) {
        attr->info.signature.signature_index = read_u16(fp);
    } else if (strcmp(attr_name, "SourceFile") == 0) {
        attr->info.source_file.sourcefile_index = read_u16(fp);
    } else if (strcmp(attr_name, "SourceDebugExtension") == 0) {
        attr->info.source_debug_extension.length = attr->attribute_length;
        attr->info.source_debug_extension.debug_extension = (uint8_t*) malloc(attr->attribute_length * sizeof(uint8_t));
        if (!attr->info.source_debug_extension.debug_extension) {
            perror("Failed to allocate memory for SourceDebugExtension");
            free(attr);
            return NULL;
        }
        if (fread(attr->info.source_debug_extension.debug_extension, sizeof(uint8_t), attr->attribute_length, fp) != attr->attribute_length) {
            perror("Error reading SourceDebugExtension bytes");
            free(attr->info.source_debug_extension.debug_extension);
            free(attr);
            return NULL;
        }
    } else if (strcmp(attr_name, "LineNumberTable") == 0) {
        attr->info.line_number_table.line_number_table_length = read_u16(fp);
        attr->info.line_number_table.line_number_table = NULL;
        if (attr->info.line_number_table.line_number_table_length > 0) {
            attr->info.line_number_table.line_number_table = (line_number_table_entry*) malloc(attr->info.line_number_table.line_number_table_length * sizeof(line_number_table_entry));
            if (!attr->info.line_number_table.line_number_table) {
                perror("Failed to allocate memory for LineNumberTable entries");
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.line_number_table.line_number_table_length; ++i) {
                attr->info.line_number_table.line_number_table[i].start_pc = read_u16(fp);
                attr->info.line_number_table.line_number_table[i].line_number = read_u16(fp);
            }
        }
    } else if (strcmp(attr_name, "LocalVariableTable") == 0) {
        attr->info.local_variable_table.local_variable_table_length = read_u16(fp);
        attr->info.local_variable_table.local_variable_table = NULL;
        if (attr->info.local_variable_table.local_variable_table_length > 0) {
            attr->info.local_variable_table.local_variable_table = (local_variable_table_entry*) malloc(attr->info.local_variable_table.local_variable_table_length * sizeof(local_variable_table_entry));
            if (!attr->info.local_variable_table.local_variable_table) {
                perror("Failed to allocate memory for LocalVariableTable entries");
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.local_variable_table.local_variable_table_length; ++i) {
                attr->info.local_variable_table.local_variable_table[i].start_pc = read_u16(fp);
                attr->info.local_variable_table.local_variable_table[i].length = read_u16(fp);
                attr->info.local_variable_table.local_variable_table[i].name_index = read_u16(fp);
                attr->info.local_variable_table.local_variable_table[i].descriptor_index = read_u16(fp);
                attr->info.local_variable_table.local_variable_table[i].index = read_u16(fp);
            }
        }
    } else if (strcmp(attr_name, "LocalVariableTypeTable") == 0) {
        attr->info.local_variable_type_table.local_variable_type_table_length = read_u16(fp);
        attr->info.local_variable_type_table.local_variable_type_table = NULL;
        if (attr->info.local_variable_type_table.local_variable_type_table_length > 0) {
            attr->info.local_variable_type_table.local_variable_type_table = (local_variable_type_table_entry*) malloc(attr->info.local_variable_type_table.local_variable_type_table_length * sizeof(local_variable_type_table_entry));
            if (!attr->info.local_variable_type_table.local_variable_type_table) {
                perror("Failed to allocate memory for LocalVariableTypeTable entries");
                free(attr);
                return NULL;
            }
            for (int i = 0; i < attr->info.local_variable_type_table.local_variable_type_table_length; ++i) {
                attr->info.local_variable_type_table.local_variable_type_table[i].start_pc = read_u16(fp);
                attr->info.local_variable_type_table.local_variable_type_table[i].length = read_u16(fp);
                attr->info.local_variable_type_table.local_variable_type_table[i].name_index = read_u16(fp);
                attr->info.local_variable_type_table.local_variable_type_table[i].signature_index = read_u16(fp);
                attr->info.local_variable_type_table.local_variable_type_table[i].index = read_u16(fp);
            }
        }
    }
    else {
        fprintf(stderr, "Warning: Unhandled attribute '%s' (length %u) at file offset 0x%lx. Skipping bytes.\n",
                attr_name, attr->attribute_length, ftell(fp) - 4 - 2); // -4 for length, -2 for name_index
        attr->info.raw_bytes = (uint8_t*) malloc(attr->attribute_length * sizeof(uint8_t));
        if (!attr->info.raw_bytes) {
            perror("Failed to allocate memory for raw bytes for unknown attribute");
            free(attr);
            return NULL;
        }
        if (fread(attr->info.raw_bytes, sizeof(uint8_t), attr->attribute_length, fp) != attr->attribute_length) {
            perror("Error reading raw bytes for unknown attribute");
            free(attr->info.raw_bytes);
            free(attr);
            return NULL;
        }
    }

    return attr;
}

// prints the contents of a single attribute
void print_attribute(const attribute_info *attr, const cp_info *constant_pool) {
    if (!attr) return;

    const char *attr_name = get_utf8_string(constant_pool, attr->attribute_name_index);
    printf("Attribute '%s' (length: %u)\n", attr_name, attr->attribute_length);

    if (strcmp(attr_name, "ConstantValue") == 0) {
        printf("        ConstantValue: #%u\n", attr->info.constant_value.constantvalue_index);
        printf("          Value: ");
        if (attr->info.constant_value.constantvalue_index > 0 && attr->info.constant_value.constantvalue_index < constant_pool_count_global) {
             print_constant_pool_entry_value(&constant_pool[attr->info.constant_value.constantvalue_index - 1], constant_pool);
        } else {
            printf("(Invalid CP index)");
        }
        printf("\n");
    } else if (strcmp(attr_name, "Code") == 0) {
        printf("        Code: max_stack=%u, max_locals=%u, code_length=%u\n",
               attr->info.code.max_stack, attr->info.code.max_locals, attr->info.code.code_length);

        if (attr->info.code.code_length > 0 && attr->info.code.code != NULL) {
            disassemble_bytecode(attr->info.code.code, attr->info.code.code_length, constant_pool, 3);
        } else {
            printf("          No code bytes.\n");
        }

        if (attr->info.code.exception_table_length > 0) {
            printf("          Exception Table (length: %u):\n", attr->info.code.exception_table_length);
            for (int i = 0; i < attr->info.code.exception_table_length; ++i) {
                printf("            [%d] start_pc=%u, end_pc=%u, handler_pc=%u, catch_type=#%u",
                       i,
                       attr->info.code.exception_table[i].start_pc,
                       attr->info.code.exception_table[i].end_pc,
                       attr->info.code.exception_table[i].handler_pc,
                       attr->info.code.exception_table[i].catch_type);
                if (attr->info.code.exception_table[i].catch_type != 0) {
                    const cp_info *class_entry = &constant_pool[attr->info.code.exception_table[i].catch_type - 1];
                    if (class_entry->tag == CONSTANT_Class) {
                        printf(" // %s", get_utf8_string(constant_pool, class_entry->info.class_info.name_index));
                    }
                }
                printf("\n");
            }
        }
        if (attr->info.code.attributes_count > 0) {
            printf("          Code Attributes (count: %u):\n", attr->info.code.attributes_count);
            for (int i = 0; i < attr->info.code.attributes_count; ++i) {
                printf("            [%d] ", i);
                print_attribute(&attr->info.code.attributes[i], constant_pool);
            }
        }
    } else if (strcmp(attr_name, "StackMapTable") == 0) {
        printf("        StackMapTable: (raw bytes, length %u)\n", attr->info.stack_map_table.length);
    } else if (strcmp(attr_name, "Exceptions") == 0) {
        printf("        Exceptions: number_of_exceptions=%u\n", attr->info.exceptions.number_of_exceptions);
        if (attr->info.exceptions.number_of_exceptions > 0) {
            printf("          Exception Index Table:\n");
            for (int i = 0; i < attr->info.exceptions.number_of_exceptions; ++i) {
                const cp_info *class_entry = &constant_pool[attr->info.exceptions.exception_index_table[i] - 1];
                 if (class_entry->tag == CONSTANT_Class) {
                    printf("            #%u // %s\n", attr->info.exceptions.exception_index_table[i],
                           get_utf8_string(constant_pool, class_entry->info.class_info.name_index));
                } else {
                    printf("            #%u // (invalid class constant)\n", attr->info.exceptions.exception_index_table[i]);
                }
            }
        }
    } else if (strcmp(attr_name, "InnerClasses") == 0) {
        printf("        InnerClasses: number_of_classes=%u\n", attr->info.inner_classes.number_of_classes);
        if (attr->info.inner_classes.number_of_classes > 0) {
            printf("          Classes:\n");
            for (int i = 0; i < attr->info.inner_classes.number_of_classes; ++i) {
                printf("            [%d] inner_class_info_index=#%u", i, attr->info.inner_classes.classes[i].inner_class_info_index);
                if (attr->info.inner_classes.classes[i].inner_class_info_index != 0) {
                    const cp_info *inner_class_entry = &constant_pool[attr->info.inner_classes.classes[i].inner_class_info_index - 1];
                    if (inner_class_entry->tag == CONSTANT_Class) {
                        printf(" // %s", get_utf8_string(constant_pool, inner_class_entry->info.class_info.name_index));
                    }
                }
                printf(", outer_class_info_index=#%u", attr->info.inner_classes.classes[i].outer_class_info_index);
                 if (attr->info.inner_classes.classes[i].outer_class_info_index != 0) {
                    const cp_info *outer_class_entry = &constant_pool[attr->info.inner_classes.classes[i].outer_class_info_index - 1];
                    if (outer_class_entry->tag == CONSTANT_Class) {
                        printf(" // %s", get_utf8_string(constant_pool, outer_class_entry->info.class_info.name_index));
                    }
                }
                printf(", inner_name_index=#%u", attr->info.inner_classes.classes[i].inner_name_index);
                if (attr->info.inner_classes.classes[i].inner_name_index != 0) {
                    printf(" // %s", get_utf8_string(constant_pool, attr->info.inner_classes.classes[i].inner_name_index));
                }
                printf(", flags=0x%04X\n", attr->info.inner_classes.classes[i].inner_class_access_flags);
            }
        }
    } else if (strcmp(attr_name, "EnclosingMethod") == 0) {
        printf("        EnclosingMethod: class_index=#%u", attr->info.enclosing_method.class_index);
        const cp_info *class_entry = &constant_pool[attr->info.enclosing_method.class_index - 1];
        if (class_entry->tag == CONSTANT_Class) {
            printf(" // %s", get_utf8_string(constant_pool, class_entry->info.class_info.name_index));
        }
        printf(", method_index=#%u", attr->info.enclosing_method.method_index);
        if (attr->info.enclosing_method.method_index != 0) {
            const cp_info *name_and_type_entry = &constant_pool[attr->info.enclosing_method.method_index - 1];
            if (name_and_type_entry->tag == CONSTANT_NameAndType) {
                printf(" // %s:%s",
                       get_utf8_string(constant_pool, name_and_type_entry->info.name_and_type_info.name_index),
                       get_utf8_string(constant_pool, name_and_type_entry->info.name_and_type_info.descriptor_index));
            }
        }
        printf("\n");
    } else if (strcmp(attr_name, "Synthetic") == 0) {
        printf("        Synthetic: (marker attribute)\n");
    } else if (strcmp(attr_name, "Signature") == 0) {
        printf("        Signature: #%u // %s\n",
               attr->info.signature.signature_index,
               get_utf8_string(constant_pool, attr->info.signature.signature_index));
    } else if (strcmp(attr_name, "SourceFile") == 0) {
        printf("        SourceFile: #%u // %s\n",
               attr->info.source_file.sourcefile_index,
               get_utf8_string(constant_pool, attr->info.source_file.sourcefile_index));
    } else if (strcmp(attr_name, "SourceDebugExtension") == 0) {
        printf("        SourceDebugExtension: (raw bytes, length %u)\n", attr->info.source_debug_extension.length);
    } else if (strcmp(attr_name, "LineNumberTable") == 0) {
        printf("        LineNumberTable: length=%u\n", attr->info.line_number_table.line_number_table_length);
        if (attr->info.line_number_table.line_number_table_length > 0) {
            for (int i = 0; i < attr->info.line_number_table.line_number_table_length; ++i) {
                printf("          [%d] start_pc=%u, line_number=%u\n",
                       i,
                       attr->info.line_number_table.line_number_table[i].start_pc,
                       attr->info.line_number_table.line_number_table[i].line_number);
            }
        }
    } else if (strcmp(attr_name, "LocalVariableTable") == 0) {
        printf("        LocalVariableTable: length=%u\n", attr->info.local_variable_table.local_variable_table_length);
        if (attr->info.local_variable_table.local_variable_table_length > 0) {
            for (int i = 0; i < attr->info.local_variable_table.local_variable_table_length; ++i) {
                printf("          [%d] start_pc=%u, len=%u, name=#%u // %s, desc=#%u // %s, index=%u\n",
                       i,
                       attr->info.local_variable_table.local_variable_table[i].start_pc,
                       attr->info.local_variable_table.local_variable_table[i].length,
                       attr->info.local_variable_table.local_variable_table[i].name_index,
                       get_utf8_string(constant_pool, attr->info.local_variable_table.local_variable_table[i].name_index),
                       attr->info.local_variable_table.local_variable_table[i].descriptor_index,
                       get_utf8_string(constant_pool, attr->info.local_variable_table.local_variable_table[i].descriptor_index),
                       attr->info.local_variable_table.local_variable_table[i].index);
            }
        }
    } else if (strcmp(attr_name, "LocalVariableTypeTable") == 0) {
        printf("        LocalVariableTypeTable: length=%u\n", attr->info.local_variable_type_table.local_variable_type_table_length);
        if (attr->info.local_variable_type_table.local_variable_type_table_length > 0) {
            for (int i = 0; i < attr->info.local_variable_type_table.local_variable_type_table_length; ++i) {
                printf("          [%d] start_pc=%u, len=%u, name=#%u // %s, sig=#%u // %s, index=%u\n",
                       i,
                       attr->info.local_variable_type_table.local_variable_type_table[i].start_pc,
                       attr->info.local_variable_type_table.local_variable_type_table[i].length,
                       attr->info.local_variable_type_table.local_variable_type_table[i].name_index,
                       get_utf8_string(constant_pool, attr->info.local_variable_type_table.local_variable_type_table[i].name_index),
                       attr->info.local_variable_type_table.local_variable_type_table[i].signature_index,
                       get_utf8_string(constant_pool, attr->info.local_variable_type_table.local_variable_type_table[i].signature_index),
                       attr->info.local_variable_type_table.local_variable_type_table[i].index);
            }
        }
    } else if (strcmp(attr_name, "Deprecated") == 0) {
        printf("        Deprecated: (marker attribute)\n");
    }
    else {
        // fallback for unhandled or raw byte attributes
        printf("        (Raw bytes, length %u)\n", attr->attribute_length);
    }
}

// free memory allocated for a single attribute.
void free_attribute(attribute_info *attr) {
    if (!attr) return;

    if (attr->info.code.code != NULL) {
        free(attr->info.code.code);
        attr->info.code.code = NULL;
    }
    if (attr->info.code.exception_table != NULL) {
        free(attr->info.code.exception_table);
        attr->info.code.exception_table = NULL;
    }
    if (attr->info.code.attributes != NULL) {
        for (int i = 0; i < attr->info.code.attributes_count; ++i) {
            free_attribute(&attr->info.code.attributes[i]);
        }
        free(attr->info.code.attributes);
        attr->info.code.attributes = NULL;
    }

    if (attr->info.stack_map_table.entries != NULL) {
        free(attr->info.stack_map_table.entries);
        attr->info.stack_map_table.entries = NULL;
    }

    if (attr->info.exceptions.exception_index_table != NULL) {
        free(attr->info.exceptions.exception_index_table);
        attr->info.exceptions.exception_index_table = NULL;
    }

    if (attr->info.inner_classes.classes != NULL) {
        free(attr->info.inner_classes.classes);
        attr->info.inner_classes.classes = NULL;
    }

    if (attr->info.source_debug_extension.debug_extension != NULL) {
        free(attr->info.source_debug_extension.debug_extension);
        attr->info.source_debug_extension.debug_extension = NULL;
    }

    if (attr->info.line_number_table.line_number_table != NULL) {
        free(attr->info.line_number_table.line_number_table);
        attr->info.line_number_table.line_number_table = NULL;
    }

    if (attr->info.local_variable_table.local_variable_table != NULL) {
        free(attr->info.local_variable_table.local_variable_table);
        attr->info.local_variable_table.local_variable_table = NULL;
    }

    if (attr->info.local_variable_type_table.local_variable_type_table != NULL) {
        free(attr->info.local_variable_type_table.local_variable_type_table);
        attr->info.local_variable_type_table.local_variable_type_table = NULL;
    }

    // default: if raw_bytes was used (for unhandled attributes), free it
    free_raw_bytes_if_present(attr);

    free(attr);
}