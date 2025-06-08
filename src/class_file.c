#include "../include/class_file.h"
#include <stdlib.h>
#include <string.h>

ClassFile* parse_class_file(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        return NULL;
    }

    ClassFile *cf = (ClassFile*) malloc(sizeof(ClassFile));
    if (!cf) {
        fclose(fp);
        return NULL;
    }

    // Read magic number
    cf->magic = read_u32(fp);
    if (cf->magic != 0xCAFEBABE) {
        fprintf(stderr, "Erro: Magic number invalido (0x%X).\n", cf->magic);
        free(cf);
        fclose(fp);
        return NULL;
    }

    // Read Versions
    cf->minor_version = read_u16(fp);
    cf->major_version = read_u16(fp);

    // Read Constant Pool Count
    cf->constant_pool_count = read_u16(fp);
    // Allocate space for constant pool
    // Using 0-indexed array, so size is count-1 (constant_pool_count is 1-indexed)
    cf->constant_pool = (cp_info*) calloc(cf->constant_pool_count, sizeof(cp_info));
    if (!cf->constant_pool) {
        free(cf);
        fclose(fp);
        return NULL;
    }

    // Parse Constant Pool
    for (int i = 1; i < cf->constant_pool_count; ++i) {
        cp_info *entry = parse_constant_pool_entry(fp);
        if (!entry) {
            free_class_file(cf); 
            fclose(fp);
            return NULL;
        }
        // Store the entry
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

    // Do Field, Method, and Class Attributes parsing
    cf->fields_count = read_u16(fp);
    // cf->fields = NULL

    cf->methods_count = read_u16(fp);
    // cf->methods = NULL; 

    cf->attributes_count = read_u16(fp);
    // cf->attributes = NULL; 

    fclose(fp);
    return cf;
}



void print_class_file_info(const ClassFile *cf) {
    if (!cf) return;
    printf("ClassFile Information:\n");
    printf("  Magic: 0x%08X\n", cf->magic);
    printf("  Major Version: %u\n", cf->major_version);
    printf("  Minor Version: %u\n", cf->minor_version);
    printf("  Constant Pool Count: %u\n", cf->constant_pool_count);

    printf("\nConstant Pool:\n");
    for (int i = 1; i < cf->constant_pool_count; ++i) {
        print_constant_pool_entry(&cf->constant_pool[i-1], i, cf->constant_pool);
        if (cf->constant_pool[i-1].tag == CONSTANT_Long || cf->constant_pool[i-1].tag == CONSTANT_Double) {
            printf("  #%d = (large constant continues)\n", i + 1); // Indicate the skipped slot
            i++; 
        }
    }

    printf("\nGeneral Details:\n");
    printf("  Access Flags: 0x%04X\n", cf->access_flags);
    const char* this_class_name = "ERROR: Invalid Class Index";
    if (cf->this_class > 0 && cf->this_class < cf->constant_pool_count &&
        cf->constant_pool[cf->this_class-1].tag == CONSTANT_Class) {
        this_class_name = get_utf8_string(cf->constant_pool, cf->constant_pool[cf->this_class-1].info.class_info.name_index);
    }
    printf("  This Class: #%u // %s\n", cf->this_class, this_class_name);

    const char* super_class_name = "ERROR: Invalid Class Index";
    if (cf->super_class > 0 && cf->super_class < cf->constant_pool_count &&
        cf->constant_pool[cf->super_class-1].tag == CONSTANT_Class) {
        super_class_name = get_utf8_string(cf->constant_pool, cf->constant_pool[cf->super_class-1].info.class_info.name_index);
    }
    printf("  Super Class: #%u // %s\n", cf->super_class, super_class_name);


    printf("  Interfaces Count: %u\n", cf->interfaces_count);
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
    printf("  Fields Count: %u\n", cf->fields_count);
    printf("  Methods Count: %u\n", cf->methods_count);
    printf("  Attributes Count: %u\n", cf->attributes_count);
}

void free_class_file(ClassFile *cf) {
    if (cf) {
        if (cf->constant_pool) {
            free_constant_pool(cf->constant_pool, cf->constant_pool_count);
        }
        if (cf->interfaces) {
            free(cf->interfaces);
        }
        free(cf);
    }
}