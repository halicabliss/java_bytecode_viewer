#include "../include/constant_pool.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>

static float u32_to_float(uint32_t val) {
    union {
        uint32_t i;
        float f;
    } conv;
    conv.i = val;
    return conv.f;
}

static uint64_t combine_u32_to_u64(uint32_t high, uint32_t low) {
    return ((uint64_t)high << 32) | low;
}

static double u64_to_double(uint64_t val) {
    union {
        uint64_t l;
        double d;
    } conv;
    conv.l = val;
    return conv.d;
}


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
            entry->info.utf8_info.bytes[entry->info.utf8_info.length] = '\0';
            break;
        }

        case CONSTANT_Integer: {
            entry->info.integer_info.bytes = read_u32(fp);
            break;
        }

        case CONSTANT_Float: {
            entry->info.float_info.bytes = read_u32(fp);
            break;
        }

        case CONSTANT_Long: {
            entry->info.long_info.high_bytes = read_u32(fp);
            entry->info.long_info.low_bytes = read_u32(fp);
            break;
        }

        case CONSTANT_Double: {
            entry->info.double_info.high_bytes = read_u32(fp);
            entry->info.double_info.low_bytes = read_u32(fp);
            break;
        }

        case CONSTANT_Class: {
            entry->info.class_info.name_index = read_u16(fp);
            break;
        }

        case CONSTANT_String: {
            entry->info.string_info.string_index = read_u16(fp);
            break;
        }

        case CONSTANT_Fieldref: {
            entry->info.fieldref_info.class_index = read_u16(fp);
            entry->info.fieldref_info.name_and_type_index = read_u16(fp);
            break;
        }

        case CONSTANT_Methodref: {
            entry->info.methodref_info.class_index = read_u16(fp);
            entry->info.methodref_info.name_and_type_index = read_u16(fp);
            break;
        }

        case CONSTANT_InterfaceMethodref: {
            entry->info.interface_methodref_info.class_index = read_u16(fp);
            entry->info.interface_methodref_info.name_and_type_index = read_u16(fp);
            break;
        }

        case CONSTANT_NameAndType: {
            entry->info.name_and_type_info.name_index = read_u16(fp);
            entry->info.name_and_type_info.descriptor_index = read_u16(fp);
            break;
        }

        case CONSTANT_MethodHandle: {
            if (fread(&entry->info.method_handle_info.reference_kind, sizeof(uint8_t), 1, fp) != 1) {
                perror("Error reading MethodHandle reference_kind");
                free(entry);
                return NULL;
            }
            entry->info.method_handle_info.reference_index = read_u16(fp);
            break;
        }
        
        case CONSTANT_MethodType: {
            entry->info.method_type_info.descriptor_index = read_u16(fp);
            break;
        }

        case CONSTANT_Dynamic: {
            entry->info.dynamic_info.bootstrap_method_attr_index = read_u16(fp);
            entry->info.dynamic_info.name_and_type_index = read_u16(fp);
            break;
        }

        case CONSTANT_InvokeDynamic: {
            entry->info.dynamic_info.bootstrap_method_attr_index = read_u16(fp);
            entry->info.dynamic_info.name_and_type_index = read_u16(fp);
            break;
        }

        case CONSTANT_Module: {
            entry->info.module_info.name_index = read_u16(fp);
            break;
        }

        case CONSTANT_Package: {
            entry->info.package_info.name_index = read_u16(fp);
            break;
        }

        default:
            // Unknown constant pool tag
            // Should NOT happen
            break;
    }
    return entry;
}

void print_constant_pool_entry(const cp_info *entry, int index, const cp_info *full_constant_pool) {
    if (!entry) return; // Should not happen if parsing is correct
    printf("  #%d = ", index);
    switch (entry->tag) {
        case CONSTANT_Utf8:
            printf("Utf8               %s\n", entry->info.utf8_info.bytes);
            break;
        case CONSTANT_Integer:
            printf("Integer            %d\n", (int32_t)entry->info.integer_info.bytes);
            break;
        case CONSTANT_Float: {
            float val = u32_to_float(entry->info.float_info.bytes);
            printf("Float              %f", val);
            if (val == 0.0f && entry->info.float_info.bytes == 0x80000000) {
                 printf(" (negative zero)");
            } else if (isnan(val)) {
                printf(" (NaN)");
            } else if (val == FLT_MAX && entry->info.float_info.bytes == 0x7f800000) {
                 printf(" (Positive Infinity)");
            } else if (val == -FLT_MAX && entry->info.float_info.bytes == 0xff800000) {
                 printf(" (Negative Infinity)");
            }
            printf("\n");
            break;
        }
        case CONSTANT_Long: {
            int64_t val = (int64_t)combine_u32_to_u64(entry->info.long_info.high_bytes, entry->info.long_info.low_bytes);
            printf("Long               %lld\n", val);
            break;
        }
        // case CONSTANT_Double: {
        //     double val = u64_to_double(combine_u32_to_u64(entry->info.double_info.high_bytes, entry->info.double_info.low_bytes));
        //     printf("Double             %lf", val);
        //     if (val == 0.0 && entry->info.double_info.bytes == 0x8000000000000000ULL) {
        //          printf(" (negative zero)");
        //     } else if (isnan(val)) {
        //         printf(" (NaN)");
        //     } else if (val == DBL_MAX && combine_u32_to_u64(entry->info.double_info.high_bytes, entry->info.double_info.low_bytes) == 0x7ff0000000000000ULL) {
        //          printf(" (Positive Infinity)");
        //     } else if (val == -DBL_MAX && combine_u32_to_u64(entry->info.double_info.high_bytes, entry->info.double_info.low_bytes) == 0xfff0000000000000ULL) {
        //          printf(" (Negative Infinity)");
        //     }
        //     printf("\n");
        //     break;
        // }
        case CONSTANT_Class: {
            const char* class_name = get_utf8_string(full_constant_pool, entry->info.class_info.name_index);
            printf("Class              #%u // %s\n", entry->info.class_info.name_index, class_name);
            break;
        }
        case CONSTANT_String: {
            const char* string_val = get_utf8_string(full_constant_pool, entry->info.string_info.string_index);
            printf("String             #%u // %s\n", entry->info.string_info.string_index, string_val);
            break;
        }
        case CONSTANT_Fieldref: {
            const char* class_name = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.fieldref_info.class_index-1].info.class_info.name_index);
            const char* name = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.fieldref_info.name_and_type_index-1].info.name_and_type_info.name_index);
            const char* descriptor = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.fieldref_info.name_and_type_index-1].info.name_and_type_info.descriptor_index);
            printf("Fieldref           #%u.#%u // %s.%s:%s\n",
                   entry->info.fieldref_info.class_index,
                   entry->info.fieldref_info.name_and_type_index,
                   class_name, name, descriptor);
            break;
        }
        case CONSTANT_Methodref: {
            const char* class_name = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.methodref_info.class_index-1].info.class_info.name_index);
            const char* name = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.methodref_info.name_and_type_index-1].info.name_and_type_info.name_index);
            const char* descriptor = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.methodref_info.name_and_type_index-1].info.name_and_type_info.descriptor_index);
            printf("Methodref          #%u.#%u // %s.%s:%s\n",
                   entry->info.methodref_info.class_index,
                   entry->info.methodref_info.name_and_type_index,
                   class_name, name, descriptor);
            break;
        }
        case CONSTANT_InterfaceMethodref: {
            const char* class_name = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.interface_methodref_info.class_index-1].info.class_info.name_index);
            const char* name = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.interface_methodref_info.name_and_type_index-1].info.name_and_type_info.name_index);
            const char* descriptor = get_utf8_string(full_constant_pool, full_constant_pool[entry->info.interface_methodref_info.name_and_type_index-1].info.name_and_type_info.descriptor_index);
            printf("InterfaceMethodref #%u.#%u // %s.%s:%s\n",
                   entry->info.interface_methodref_info.class_index,
                   entry->info.interface_methodref_info.name_and_type_index,
                   class_name, name, descriptor);
            break;
        }
        case CONSTANT_NameAndType: {
            const char* name = get_utf8_string(full_constant_pool, entry->info.name_and_type_info.name_index);
            const char* descriptor = get_utf8_string(full_constant_pool, entry->info.name_and_type_info.descriptor_index);
            printf("NameAndType        #%u:#%u // %s:%s\n",
                   entry->info.name_and_type_info.name_index,
                   entry->info.name_and_type_info.descriptor_index,
                   name, descriptor);
            break;
        }
        case CONSTANT_MethodHandle:
            printf("MethodHandle       %u:#%u\n",
                   entry->info.method_handle_info.reference_kind,
                   entry->info.method_handle_info.reference_index);
            break;
        case CONSTANT_MethodType: {
            const char* descriptor = get_utf8_string(full_constant_pool, entry->info.method_type_info.descriptor_index);
            printf("MethodType         #%u // %s\n",
                   entry->info.method_type_info.descriptor_index, descriptor);
            break;
        }
        case CONSTANT_Dynamic:
            printf("Dynamic            #%u:#%u\n",
                   entry->info.dynamic_info.bootstrap_method_attr_index,
                   entry->info.dynamic_info.name_and_type_index);
            break;
        case CONSTANT_InvokeDynamic:
            printf("InvokeDynamic      #%u:#%u\n",
                   entry->info.invoke_dynamic_info.bootstrap_method_attr_index,
                   entry->info.invoke_dynamic_info.name_and_type_index);
            break;
        case CONSTANT_Module: {
            const char* name = get_utf8_string(full_constant_pool, entry->info.module_info.name_index);
            printf("Module             #%u // %s\n", entry->info.module_info.name_index, name);
            break;
        }
        case CONSTANT_Package: {
            const char* name = get_utf8_string(full_constant_pool, entry->info.package_info.name_index);
            printf("Package            #%u // %s\n", entry->info.package_info.name_index, name);
            break;
        }
        default:
            printf("Unknown_Constant_Type (tag %u)\n", entry->tag);
            break;
    }
}


void free_constant_pool(cp_info *constant_pool, uint16_t count) {
    if (constant_pool) {
        for (int i = 0; i < count - 1; ++i) {
            switch (constant_pool[i].tag) {
                case CONSTANT_Utf8:
                    free(constant_pool[i].info.utf8_info.bytes);
                    break;
                case CONSTANT_Long:
                case CONSTANT_Double:
                    break;
                default:
                    break;
            }
        }
        free(constant_pool);
    }
}

const char* get_utf8_string(const cp_info *constant_pool, uint16_t index) {
    if (index == 0 || index >= (UINT16_MAX-1)) {
        return "INVALID_CP_INDEX";
    }
    const cp_info *entry = &constant_pool[index-1];
    if (entry->tag == CONSTANT_Utf8) {
        return (const char*)entry->info.utf8_info.bytes;
    }
    return "NOT_UTF8";
}