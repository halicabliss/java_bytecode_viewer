#include "../include/constant_pool.h"
#include <stdlib.h> 
#include <string.h>

cp_info* parse_constant_pool_entry(FILE *fp) {
    cp_info *entry = (cp_info*) malloc(sizeof(cp_info));
    if (!entry) {
        return NULL;
    }

    if (fread(&entry->tag, sizeof(uint8_t), 1, fp) != 1) {
        free(entry);
        return NULL;
    }

    switch (entry->tag) {
        case CONSTANT_Utf8: {
            entry->info.utf8_info.length = read_u16(fp);
            entry->info.utf8_info.bytes = (uint8_t*) malloc(entry->info.utf8_info.length + 1);
            if (!entry->info.utf8_info.bytes) {
                free(entry);
                return NULL;
            }
            if (fread(entry->info.utf8_info.bytes, sizeof(uint8_t), entry->info.utf8_info.length, fp) != entry->info.utf8_info.length) {
                free(entry->info.utf8_info.bytes);
                free(entry);
                return NULL;
            }
            entry->info.utf8_info.bytes[entry->info.utf8_info.length] = '\0'; // Null-terminate
            break;
        }

        // Add cases for other constant types

        default:
            // Unknown constant pool tag
            break;
    }
    return entry;
}

void print_constant_pool_entry(const cp_info *entry, int index) {
    printf("  #%d = ", index);
    switch (entry->tag) {
        case CONSTANT_Utf8:
            printf("Utf8               %s\n", entry->info.utf8_info.bytes);
            break;
        // Add print cases for other constant types
        default:
            // Unknown constant pool tag
            break;
    }
}

void free_constant_pool(cp_info *constant_pool, uint16_t count) {
    if (constant_pool) {
        for (int i = 0; i < count; ++i) {
            if (constant_pool[i].tag == CONSTANT_Utf8) {
                free(constant_pool[i].info.utf8_info.bytes);
            }
            // Free memory for other constant types if they allocate memory
        }
        free(constant_pool);
    }
}

const char* get_utf8_string(const cp_info *constant_pool, uint16_t index) {
    if (index >= 1 && constant_pool[index-1].tag == CONSTANT_Utf8) {
        return (const char*)constant_pool[index-1].info.utf8_info.bytes;
    }
    return "Invalid Utf8 Index";
}