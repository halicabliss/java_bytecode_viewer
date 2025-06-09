#ifndef BYTECODE_DISASSEMBLER_H
#define BYTECODE_DISASSEMBLER_H

#include <stdint.h>
#include <stdio.h> 
#include "constant_pool.h"

void disassemble_bytecode(const uint8_t *code, uint32_t code_length, const cp_info *constant_pool, int indent_level);

#endif // BYTECODE_DISASSEMBLER_H