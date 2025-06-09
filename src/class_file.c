#include "../include/class_file.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h> 

#include "../include/common.h"
#include "../include/constant_pool.h"
#include "../include/fields.h"
#include "../include/methods.h"
#include "../include/attributes.h"

uint16_t constant_pool_count_global = 0;

ClassFile* parse_class_file(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        perror("Failed to open class file");
        return NULL;
    }

    ClassFile *cf = (ClassFile*) malloc(sizeof(ClassFile));
    if (!cf) {
        perror("Failed to allocate memory for ClassFile");
        fclose(fp);
        return NULL;
    }

    cf->constant_pool = NULL;
    cf->interfaces = NULL;
    cf->fields = NULL;
    cf->methods = NULL;
    cf->attributes = NULL;

    // Read magic number
    cf->magic = read_u32(fp);
    if (cf->magic != 0xCAFEBABE) {
        fprintf(stderr, "Error: Invalid magic number (0x%08X). Expected 0xCAFEBABE.\n", cf->magic);
        free_class_file(cf);
        fclose(fp);
        return NULL;
    }

    // Read Versions
    cf->minor_version = read_u16(fp);
    cf->major_version = read_u16(fp);

    // Read Constant Pool Count
    cf->constant_pool_count = read_u16(fp);
    constant_pool_count_global = cf->constant_pool_count;
    cf->constant_pool = (cp_info*) calloc(cf->constant_pool_count, sizeof(cp_info));
    if (!cf->constant_pool) {
        perror("Failed to allocate memory for constant pool");
        free_class_file(cf);
        fclose(fp);
        return NULL;
    }

    // Parse Constant Pool
    for (int i = 1; i < cf->constant_pool_count; ++i) {
        cp_info *entry = parse_constant_pool_entry(fp);
        if (!entry) {
            fprintf(stderr, "Error parsing constant pool entry #%d.\n", i);
            free_class_file(cf);
            fclose(fp);
            return NULL; 
        }
        memcpy(&cf->constant_pool[i-1], entry, sizeof(cp_info));
        free(entry);

        if (cf->constant_pool[i-1].tag == CONSTANT_Long || cf->constant_pool[i-1].tag == CONSTANT_Double) {
            i++;
        }
    }

    // Read Access Flags, This Class, Super Class, Interfaces
    cf->access_flags = read_u16(fp);
    cf->this_class = read_u16(fp);
    cf->super_class = read_u16(fp);
    cf->interfaces_count = read_u16(fp);

    // Allocate and read interfaces
    if (cf->interfaces_count > 0) {
        cf->interfaces = (uint16_t*) malloc(cf->interfaces_count * sizeof(uint16_t));
        if (!cf->interfaces) {
            perror("Failed to allocate memory for interfaces");
            free_class_file(cf);
            fclose(fp);
            return NULL;
        }
        for (int i = 0; i < cf->interfaces_count; ++i) {
            cf->interfaces[i] = read_u16(fp);
        }
    } else {
        cf->interfaces = NULL;
    }

    // Parse Fields
    cf->fields_count = read_u16(fp);
    if (cf->fields_count > 0) {
        cf->fields = (field_info*) malloc(cf->fields_count * sizeof(field_info));
        if (!cf->fields) {
            perror("Failed to allocate memory for fields");
            free_class_file(cf);
            fclose(fp);
            return NULL;
        }
        for (int i = 0; i < cf->fields_count; ++i) {
            field_info *f = parse_field_info(fp, cf->constant_pool);
            if (!f) {
                fprintf(stderr, "Error parsing field #%d.\n", i);
                for (int j = 0; j < i; ++j) {
                    free_field_info(&cf->fields[j]);
                }
                free(cf->fields);
                cf->fields = NULL;
                free_class_file(cf);
                fclose(fp);
                return NULL;
            }
            memcpy(&cf->fields[i], f, sizeof(field_info));
            free(f);
        }
    } else {
        cf->fields = NULL;
    }


    // Parse Methods
    cf->methods_count = read_u16(fp);
    if (cf->methods_count > 0) {
        cf->methods = (method_info*) malloc(cf->methods_count * sizeof(method_info));
        if (!cf->methods) {
            perror("Failed to allocate memory for methods");
            free_class_file(cf);
            fclose(fp);
            return NULL;
        }
        for (int i = 0; i < cf->methods_count; ++i) {
            method_info *m = parse_method_info(fp, cf->constant_pool);
            if (!m) {
                fprintf(stderr, "Error parsing method #%d.\n", i);
                for (int j = 0; j < i; ++j) {
                    free_method_info(&cf->methods[j]);
                }
                free(cf->methods);
                cf->methods = NULL;
                free_class_file(cf);
                fclose(fp);
                return NULL;
            }
            memcpy(&cf->methods[i], m, sizeof(method_info));
            free(m);
        }
    } else {
        cf->methods = NULL;
    }

    // Parse Class-level Attributes
    cf->attributes_count = read_u16(fp);
    if (cf->attributes_count > 0) {
        cf->attributes = (attribute_info*) malloc(cf->attributes_count * sizeof(attribute_info));
        if (!cf->attributes) {
            perror("Failed to allocate memory for class attributes");
            free_class_file(cf);
            fclose(fp);
            return NULL;
        }
        for (int i = 0; i < cf->attributes_count; ++i) {
            attribute_info *a = parse_attribute(fp, cf->constant_pool);
            if (!a) {
                fprintf(stderr, "Error parsing class attribute #%d.\n", i);
                for (int j = 0; j < i; ++j) {
                    free_attribute(&cf->attributes[j]);
                }
                free(cf->attributes);
                cf->attributes = NULL;
                free_class_file(cf);
                fclose(fp);
                return NULL;
            }
            memcpy(&cf->attributes[i], a, sizeof(attribute_info));
            free(a);
        }
    } else {
        cf->attributes = NULL;
    }

    fclose(fp);
    return cf;
}


static const char* get_class_access_flags_string(uint16_t flags) {
    static char buffer[128];
    buffer[0] = '\0';

    if (flags & ACC_PUBLIC) strcat(buffer, "public ");
    if (flags & ACC_FINAL) strcat(buffer, "final ");
    if (flags & ACC_SUPER) strcat(buffer, "super ");
    if (flags & ACC_INTERFACE) strcat(buffer, "interface ");
    if (flags & ACC_ABSTRACT) strcat(buffer, "abstract ");
    if (flags & ACC_SYNTHETIC) strcat(buffer, "synthetic ");
    if (flags & ACC_ANNOTATION) strcat(buffer, "annotation ");
    if (flags & ACC_ENUM) strcat(buffer, "enum ");
    if (flags & ACC_MODULE) strcat(buffer, "module ");

    if (strlen(buffer) > 0) {
        buffer[strlen(buffer) - 1] = '\0';
    } else {
        strcat(buffer, "(no flags)");
    }
    return buffer;
}


void print_class_file_info(const ClassFile *cf) {
    if (!cf) return;
    printf("--- ClassFile Information ---\n");
    printf("  Magic: 0x%08X\n", cf->magic);
    printf("  Minor Version: %u\n", cf->minor_version);
    printf("  Major Version: %u (Java %u)\n", cf->major_version, cf->major_version - 44);
    printf("  Constant Pool Count: %u\n", cf->constant_pool_count);

    printf("\n--- Constant Pool ---\n");
    for (int i = 1; i < cf->constant_pool_count; ++i) {
        printf("  #%d = ", i);
        print_constant_pool_entry(&cf->constant_pool[i-1], i, cf->constant_pool);
        if (cf->constant_pool[i-1].tag == CONSTANT_Long || cf->constant_pool[i-1].tag == CONSTANT_Double) {
            printf("  #%d = (large constant continues)\n", i + 1);
            i++;
        }
    }

    printf("\n--- General Details ---\n");
    printf("  Access Flags: 0x%04X (%s)\n", cf->access_flags, get_class_access_flags_string(cf->access_flags));

    const char* this_class_name = "ERROR: Invalid Class Index";
    if (cf->this_class > 0 && cf->this_class < cf->constant_pool_count &&
        cf->constant_pool[cf->this_class-1].tag == CONSTANT_Class) {
        this_class_name = get_utf8_string(cf->constant_pool, cf->constant_pool[cf->this_class-1].info.class_info.name_index);
    }
    printf("  This Class: #%u // %s\n", cf->this_class, this_class_name);

    const char* super_class_name = "ERROR: Invalid Class Index";
    if (cf->super_class == 0) {
        super_class_name = "java/lang/Object";
    } else if (cf->super_class > 0 && cf->super_class < cf->constant_pool_count &&
        cf->constant_pool[cf->super_class-1].tag == CONSTANT_Class) {
        super_class_name = get_utf8_string(cf->constant_pool, cf->constant_pool[cf->super_class-1].info.class_info.name_index);
    }
    printf("  Super Class: #%u // %s\n", cf->super_class, super_class_name);


    printf("\n  Interfaces Count: %u\n", cf->interfaces_count);
    if (cf->interfaces_count > 0) {
        printf("  Interfaces:\n");
        for (int i = 0; i < cf->interfaces_count; ++i) {
            const char* interface_name = "ERROR: Invalid Interface Index";
            if (cf->interfaces[i] > 0 && cf->interfaces[i] < cf->constant_pool_count &&
                cf->constant_pool[cf->interfaces[i]-1].tag == CONSTANT_Class) {
                interface_name = get_utf8_string(cf->constant_pool, cf->constant_pool[cf->interfaces[i]-1].info.class_info.name_index);
            }
            printf("    #%u // %s\n", cf->interfaces[i], interface_name);
        }
    }

    // Print Fields
    printf("\n  Fields Count: %u\n", cf->fields_count);
    if (cf->fields_count > 0) {
        printf("  Fields:\n");
        for (int i = 0; i < cf->fields_count; ++i) {
            printf("    [%d] ", i);
            print_field_info(&cf->fields[i], cf->constant_pool);
        }
    }

    // Print Methods
    printf("\n  Methods Count: %u\n", cf->methods_count);
    if (cf->methods_count > 0) {
        printf("  Methods:\n");
        for (int i = 0; i < cf->methods_count; ++i) {
            printf("    [%d] ", i);
            print_method_info(&cf->methods[i], cf->constant_pool);
        }
    }
    printf("\n  Attributes Count: %u\n", cf->attributes_count);

    // Print Class-level Attributes
    printf("  Attributes Count: %u\n", cf->attributes_count);
    if (cf->attributes_count > 0) {
        printf("  Class Attributes:\n");
        for (int i = 0; i < cf->attributes_count; ++i) {
            printf("    [%d] ", i);
            print_attribute(&cf->attributes[i], cf->constant_pool);
        }
    }
}

void free_class_file(ClassFile *cf) {
    if (cf) {
        if (cf->constant_pool) {
            free_constant_pool(cf->constant_pool, cf->constant_pool_count);
        }
        if (cf->interfaces) {
            free(cf->interfaces);
            cf->interfaces = NULL;
        }
        
        // Free Fields
        if (cf->fields) {
            for (int i = 0; i < cf->fields_count; ++i) {
                free_field_info(&cf->fields[i]);
            }
            free(cf->fields);
            cf->fields = NULL;
        }

        // Free Methods
        if (cf->methods) {
            for (int i = 0; i < cf->methods_count; ++i) {
                free_method_info(&cf->methods[i]);
            }
            free(cf->methods);
            cf->methods = NULL;
        }   
        
        // Free Class-level Attributes
        if (cf->attributes) {
            for (int i = 0; i < cf->attributes_count; ++i) {
                free_attribute(&cf->attributes[i]);
            }
            free(cf->attributes);
            cf->attributes = NULL;
        }

        free(cf);
    }
}