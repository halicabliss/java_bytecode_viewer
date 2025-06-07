#include <stdio.h>
#include <stdlib.h>
#include "../include/class_file.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <arquivo_class>\n", argv[0]);
        return -1;
    }
    
    const char *filepath = argv[1];
    ClassFile *cf = parse_class_file(filepath);

    if (cf) {
        print_class_file_info(cf);
        free_class_file(cf);
    } else {
        fprintf(stderr, "Erro ao ler arquivo: %s\n", filepath);
        return -1;
    }

    return 0;
}