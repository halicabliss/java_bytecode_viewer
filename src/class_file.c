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
        // Handle CONSTANT_Long_info and CONSTANT_Double_info which occupy two slots
        if (entry->tag == CONSTANT_Long || entry->tag == CONSTANT_Double) {
            // Store the entry
            memcpy(&cf->constant_pool[i-1], entry, sizeof(cp_info));
            free(entry);
            i++;
            //
        } else {
            memcpy(&cf->constant_pool[i-1], entry, sizeof(cp_info));
            free(entry); 
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
    // Loop up to constant_pool_count starting with index 1
    for (int i = 1; i < cf->constant_pool_count; ++i) {
        // Handle long/double occupying two slots (print only the first one)
        if (cf->constant_pool[i-1].tag == CONSTANT_Long || cf->constant_pool[i-1].tag == CONSTANT_Double) {
            print_constant_pool_entry(&cf->constant_pool[i-1], i);
            i++; // Skip the next slot
        } else {
            print_constant_pool_entry(&cf->constant_pool[i-1], i);
        }
    }

    printf("\nGeneral Details:\n");
    printf("  Access Flags: 0x%04X\n", cf->access_flags);
    //printf("  This Class: #%u // %s\n", cf->this_class, get_utf8_string(cf->constant_pool, cf->constant_pool[cf->this_class-1].info.class_info.name_index)); 
    //printf("  Super Class: #%u // %s\n", cf->super_class, get_utf8_string(cf->constant_pool, cf->constant_pool[cf->super_class-1].info.class_info.name_index)); 
    printf("  Interfaces Count: %u\n", cf->interfaces_count);
    if (cf->interfaces_count > 0) {
        printf("  Interfaces:\n");
        for (int i = 0; i < cf->interfaces_count; ++i) {
            //printf("    #%u // %s\n", cf->interfaces[i], get_utf8_string(cf->constant_pool, cf->constant_pool[cf->interfaces[i]-1].info.class_info.name_index));
        }
    }
    printf("  Fields Count: %u\n", cf->fields_count);
    printf("  Methods Count: %u\n", cf->methods_count);
    printf("  Attributes Count: %u\n", cf->attributes_count);
}


void free_class_file(ClassFile *cf) {
    if (cf) {
        if (cf->constant_pool) {
            // Free constant pool entries
            for (int i = 0; i < cf->constant_pool_count -1; ++i) {
                 if (cf->constant_pool[i].tag == CONSTANT_Utf8) {
                    free(cf->constant_pool[i].info.utf8_info.bytes);
                 }
                 // Handle other constant types that allocate memory
            }
            free(cf->constant_pool);
        }
        if (cf->interfaces) {
            free(cf->interfaces);
        }
        // Free fields, methods, and attributes when implemented
        free(cf);
    }
}