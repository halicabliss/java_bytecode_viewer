#include "../include/bytecode_disassembler.h"
#include "../include/constant_pool.h"
#include "../include/common.h"

#include <stdio.h>
#include <string.h>

typedef enum {
    OP_NONE,          // No operands
    OP_BYTE,          // 1-byte operand
    OP_SHORT,         // 2-byte operand (read as signed short)
    OP_CP_INDEX_BYTE, // 1-byte constant pool index
    OP_CP_INDEX_SHORT,// 2-byte constant pool index
    OP_LOCAL_INDEX_BYTE, // 1-byte local variable index
    OP_BRANCH_SHORT,  // 2-byte signed branch offset
    OP_BRANCH_INT,    // 4-byte signed branch offset
    OP_IINC,          // iinc: 1-byte local var index, 1-byte constant
    OP_LOOKUPSWITCH,  // tableswitch: variable length, default, npairs, pairs...
    OP_TABLESWITCH,   // lookupswitch: variable length, default, low, high, jump offsets...
    OP_MULTIANEWARRAY, // multianewarray: 2-byte CP index, 1-byte dimensions
    OP_INVOKEINTERFACE, // invokeinterface: 2-byte CP index, 1-byte count, 1-byte 0
    OP_INVOKEDYNAMIC,   // invokedynamic: 2-byte CP index, 2-byte 0
    OP_WIDE           // wide prefix (changes next instruction's operand size)
} OperandType;

// Structure to hold information about each opcode
typedef struct {
    const char *mnemonic;
    int operand_bytes; // number of bytes AFTER the opcode byte itself
    OperandType op_type;
} opcode_info;

static opcode_info opcode_table[256];

static void initialize_opcode_table() {
    static int initialized = 0;
    if (initialized) return;

    for (int i = 0; i < 256; ++i) {
        opcode_table[i] = (opcode_info){.mnemonic = "invalid", .operand_bytes = 0, .op_type = OP_NONE};
    }


    // No operands (operand_bytes = 0)
    opcode_table[0x00].mnemonic = "nop"; opcode_table[0x00].operand_bytes = 0; opcode_table[0x00].op_type = OP_NONE;
    opcode_table[0x01].mnemonic = "aconst_null"; opcode_table[0x01].operand_bytes = 0; opcode_table[0x01].op_type = OP_NONE;
    opcode_table[0x02].mnemonic = "iconst_m1"; opcode_table[0x02].operand_bytes = 0; opcode_table[0x02].op_type = OP_NONE;
    opcode_table[0x03].mnemonic = "iconst_0"; opcode_table[0x03].operand_bytes = 0; opcode_table[0x03].op_type = OP_NONE;
    opcode_table[0x04].mnemonic = "iconst_1"; opcode_table[0x04].operand_bytes = 0; opcode_table[0x04].op_type = OP_NONE;
    opcode_table[0x05].mnemonic = "iconst_2"; opcode_table[0x05].operand_bytes = 0; opcode_table[0x05].op_type = OP_NONE;
    opcode_table[0x06].mnemonic = "iconst_3"; opcode_table[0x06].operand_bytes = 0; opcode_table[0x06].op_type = OP_NONE;
    opcode_table[0x07].mnemonic = "iconst_4"; opcode_table[0x07].operand_bytes = 0; opcode_table[0x07].op_type = OP_NONE;
    opcode_table[0x08].mnemonic = "iconst_5"; opcode_table[0x08].operand_bytes = 0; opcode_table[0x08].op_type = OP_NONE;
    opcode_table[0x09].mnemonic = "lconst_0"; opcode_table[0x09].operand_bytes = 0; opcode_table[0x09].op_type = OP_NONE;
    opcode_table[0x0a].mnemonic = "lconst_1"; opcode_table[0x0a].operand_bytes = 0; opcode_table[0x0a].op_type = OP_NONE;
    opcode_table[0x0b].mnemonic = "fconst_0"; opcode_table[0x0b].operand_bytes = 0; opcode_table[0x0b].op_type = OP_NONE;
    opcode_table[0x0c].mnemonic = "fconst_1"; opcode_table[0x0c].operand_bytes = 0; opcode_table[0x0c].op_type = OP_NONE;
    opcode_table[0x0d].mnemonic = "fconst_2"; opcode_table[0x0d].operand_bytes = 0; opcode_table[0x0d].op_type = OP_NONE;
    opcode_table[0x0e].mnemonic = "dconst_0"; opcode_table[0x0e].operand_bytes = 0; opcode_table[0x0e].op_type = OP_NONE;
    opcode_table[0x0f].mnemonic = "dconst_1"; opcode_table[0x0f].operand_bytes = 0; opcode_table[0x0f].op_type = OP_NONE;

    // 1-byte operand
    opcode_table[0x10].mnemonic = "bipush"; opcode_table[0x10].operand_bytes = 1; opcode_table[0x10].op_type = OP_BYTE;
    opcode_table[0x11].mnemonic = "sipush"; opcode_table[0x11].operand_bytes = 2; opcode_table[0x11].op_type = OP_SHORT; // NOTE: sipush takes a short, not a byte

    // Load instructions (variable, but _<n> versions have 0 operands, others 1)
    opcode_table[0x12].mnemonic = "ldc"; opcode_table[0x12].operand_bytes = 1; opcode_table[0x12].op_type = OP_CP_INDEX_BYTE; // ldc takes 1-byte index
    opcode_table[0x13].mnemonic = "ldc_w"; opcode_table[0x13].operand_bytes = 2; opcode_table[0x13].op_type = OP_CP_INDEX_SHORT; // ldc_w takes 2-byte index
    opcode_table[0x14].mnemonic = "ldc2_w"; opcode_table[0x14].operand_bytes = 2; opcode_table[0x14].op_type = OP_CP_INDEX_SHORT; // ldc2_w takes 2-byte index

    opcode_table[0x15].mnemonic = "iload"; opcode_table[0x15].operand_bytes = 1; opcode_table[0x15].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x16].mnemonic = "lload"; opcode_table[0x16].operand_bytes = 1; opcode_table[0x16].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x17].mnemonic = "fload"; opcode_table[0x17].operand_bytes = 1; opcode_table[0x17].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x18].mnemonic = "dload"; opcode_table[0x18].operand_bytes = 1; opcode_table[0x18].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x19].mnemonic = "aload"; opcode_table[0x19].operand_bytes = 1; opcode_table[0x19].op_type = OP_LOCAL_INDEX_BYTE;

    opcode_table[0x1a].mnemonic = "iload_0"; opcode_table[0x1a].operand_bytes = 0; opcode_table[0x1a].op_type = OP_NONE;
    opcode_table[0x1b].mnemonic = "iload_1"; opcode_table[0x1b].operand_bytes = 0; opcode_table[0x1b].op_type = OP_NONE;
    opcode_table[0x1c].mnemonic = "iload_2"; opcode_table[0x1c].operand_bytes = 0; opcode_table[0x1c].op_type = OP_NONE;
    opcode_table[0x1d].mnemonic = "iload_3"; opcode_table[0x1d].operand_bytes = 0; opcode_table[0x1d].op_type = OP_NONE;
    opcode_table[0x1e].mnemonic = "lload_0"; opcode_table[0x1e].operand_bytes = 0; opcode_table[0x1e].op_type = OP_NONE;
    opcode_table[0x1f].mnemonic = "lload_1"; opcode_table[0x1f].operand_bytes = 0; opcode_table[0x1f].op_type = OP_NONE;
    opcode_table[0x20].mnemonic = "lload_2"; opcode_table[0x20].operand_bytes = 0; opcode_table[0x20].op_type = OP_NONE;
    opcode_table[0x21].mnemonic = "lload_3"; opcode_table[0x21].operand_bytes = 0; opcode_table[0x21].op_type = OP_NONE;
    opcode_table[0x22].mnemonic = "fload_0"; opcode_table[0x22].operand_bytes = 0; opcode_table[0x22].op_type = OP_NONE;
    opcode_table[0x23].mnemonic = "fload_1"; opcode_table[0x23].operand_bytes = 0; opcode_table[0x23].op_type = OP_NONE;
    opcode_table[0x24].mnemonic = "fload_2"; opcode_table[0x24].operand_bytes = 0; opcode_table[0x24].op_type = OP_NONE;
    opcode_table[0x25].mnemonic = "fload_3"; opcode_table[0x25].operand_bytes = 0; opcode_table[0x25].op_type = OP_NONE;
    opcode_table[0x26].mnemonic = "dload_0"; opcode_table[0x26].operand_bytes = 0; opcode_table[0x26].op_type = OP_NONE;
    opcode_table[0x27].mnemonic = "dload_1"; opcode_table[0x27].operand_bytes = 0; opcode_table[0x27].op_type = OP_NONE;
    opcode_table[0x28].mnemonic = "dload_2"; opcode_table[0x28].operand_bytes = 0; opcode_table[0x28].op_type = OP_NONE;
    opcode_table[0x29].mnemonic = "dload_3"; opcode_table[0x29].operand_bytes = 0; opcode_table[0x29].op_type = OP_NONE;
    opcode_table[0x2a].mnemonic = "aload_0"; opcode_table[0x2a].operand_bytes = 0; opcode_table[0x2a].op_type = OP_NONE;
    opcode_table[0x2b].mnemonic = "aload_1"; opcode_table[0x2b].operand_bytes = 0; opcode_table[0x2b].op_type = OP_NONE;
    opcode_table[0x2c].mnemonic = "aload_2"; opcode_table[0x2c].operand_bytes = 0; opcode_table[0x2c].op_type = OP_NONE;
    opcode_table[0x2d].mnemonic = "aload_3"; opcode_table[0x2d].operand_bytes = 0; opcode_table[0x2d].op_type = OP_NONE;

    // Array load instructions
    opcode_table[0x2e].mnemonic = "iaload"; opcode_table[0x2e].operand_bytes = 0; opcode_table[0x2e].op_type = OP_NONE;
    opcode_table[0x2f].mnemonic = "laload"; opcode_table[0x2f].operand_bytes = 0; opcode_table[0x2f].op_type = OP_NONE;
    opcode_table[0x30].mnemonic = "faload"; opcode_table[0x30].operand_bytes = 0; opcode_table[0x30].op_type = OP_NONE;
    opcode_table[0x31].mnemonic = "daload"; opcode_table[0x31].operand_bytes = 0; opcode_table[0x31].op_type = OP_NONE;
    opcode_table[0x32].mnemonic = "aaload"; opcode_table[0x32].operand_bytes = 0; opcode_table[0x32].op_type = OP_NONE;
    opcode_table[0x33].mnemonic = "baload"; opcode_table[0x33].operand_bytes = 0; opcode_table[0x33].op_type = OP_NONE;
    opcode_table[0x34].mnemonic = "caload"; opcode_table[0x34].operand_bytes = 0; opcode_table[0x34].op_type = OP_NONE;
    opcode_table[0x35].mnemonic = "saload"; opcode_table[0x35].operand_bytes = 0; opcode_table[0x35].op_type = OP_NONE;

    // Store instructions
    opcode_table[0x36].mnemonic = "istore"; opcode_table[0x36].operand_bytes = 1; opcode_table[0x36].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x37].mnemonic = "lstore"; opcode_table[0x37].operand_bytes = 1; opcode_table[0x37].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x38].mnemonic = "fstore"; opcode_table[0x38].operand_bytes = 1; opcode_table[0x38].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x39].mnemonic = "dstore"; opcode_table[0x39].operand_bytes = 1; opcode_table[0x39].op_type = OP_LOCAL_INDEX_BYTE;
    opcode_table[0x3a].mnemonic = "astore"; opcode_table[0x3a].operand_bytes = 1; opcode_table[0x3a].op_type = OP_LOCAL_INDEX_BYTE;

    opcode_table[0x3b].mnemonic = "istore_0"; opcode_table[0x3b].operand_bytes = 0; opcode_table[0x3b].op_type = OP_NONE;
    opcode_table[0x3c].mnemonic = "istore_1"; opcode_table[0x3c].operand_bytes = 0; opcode_table[0x3c].op_type = OP_NONE;
    opcode_table[0x3d].mnemonic = "istore_2"; opcode_table[0x3d].operand_bytes = 0; opcode_table[0x3d].op_type = OP_NONE;
    opcode_table[0x3e].mnemonic = "istore_3"; opcode_table[0x3e].operand_bytes = 0; opcode_table[0x3e].op_type = OP_NONE;
    opcode_table[0x3f].mnemonic = "lstore_0"; opcode_table[0x3f].operand_bytes = 0; opcode_table[0x3f].op_type = OP_NONE;
    opcode_table[0x40].mnemonic = "lstore_1"; opcode_table[0x40].operand_bytes = 0; opcode_table[0x40].op_type = OP_NONE;
    opcode_table[0x41].mnemonic = "lstore_2"; opcode_table[0x41].operand_bytes = 0; opcode_table[0x41].op_type = OP_NONE;
    opcode_table[0x42].mnemonic = "lstore_3"; opcode_table[0x42].operand_bytes = 0; opcode_table[0x42].op_type = OP_NONE;
    opcode_table[0x43].mnemonic = "fstore_0"; opcode_table[0x43].operand_bytes = 0; opcode_table[0x43].op_type = OP_NONE;
    opcode_table[0x44].mnemonic = "fstore_1"; opcode_table[0x44].operand_bytes = 0; opcode_table[0x44].op_type = OP_NONE;
    opcode_table[0x45].mnemonic = "fstore_2"; opcode_table[0x45].operand_bytes = 0; opcode_table[0x45].op_type = OP_NONE;
    opcode_table[0x46].mnemonic = "fstore_3"; opcode_table[0x46].operand_bytes = 0; opcode_table[0x46].op_type = OP_NONE;
    opcode_table[0x47].mnemonic = "dstore_0"; opcode_table[0x47].operand_bytes = 0; opcode_table[0x47].op_type = OP_NONE;
    opcode_table[0x48].mnemonic = "dstore_1"; opcode_table[0x48].operand_bytes = 0; opcode_table[0x48].op_type = OP_NONE;
    opcode_table[0x49].mnemonic = "dstore_2"; opcode_table[0x49].operand_bytes = 0; opcode_table[0x49].op_type = OP_NONE;
    opcode_table[0x4a].mnemonic = "dstore_3"; opcode_table[0x4a].operand_bytes = 0; opcode_table[0x4a].op_type = OP_NONE;
    opcode_table[0x4b].mnemonic = "astore_0"; opcode_table[0x4b].operand_bytes = 0; opcode_table[0x4b].op_type = OP_NONE;
    opcode_table[0x4c].mnemonic = "astore_1"; opcode_table[0x4c].operand_bytes = 0; opcode_table[0x4c].op_type = OP_NONE;
    opcode_table[0x4d].mnemonic = "astore_2"; opcode_table[0x4d].operand_bytes = 0; opcode_table[0x4d].op_type = OP_NONE;
    opcode_table[0x4e].mnemonic = "astore_3"; opcode_table[0x4e].operand_bytes = 0; opcode_table[0x4e].op_type = OP_NONE;

    // Array store instructions
    opcode_table[0x4f].mnemonic = "iastore"; opcode_table[0x4f].operand_bytes = 0; opcode_table[0x4f].op_type = OP_NONE;
    opcode_table[0x50].mnemonic = "lastore"; opcode_table[0x50].operand_bytes = 0; opcode_table[0x50].op_type = OP_NONE;
    opcode_table[0x51].mnemonic = "fastore"; opcode_table[0x51].operand_bytes = 0; opcode_table[0x51].op_type = OP_NONE;
    opcode_table[0x52].mnemonic = "dastore"; opcode_table[0x52].operand_bytes = 0; opcode_table[0x52].op_type = OP_NONE;
    opcode_table[0x53].mnemonic = "aastore"; opcode_table[0x53].operand_bytes = 0; opcode_table[0x53].op_type = OP_NONE;
    opcode_table[0x54].mnemonic = "bastore"; opcode_table[0x54].operand_bytes = 0; opcode_table[0x54].op_type = OP_NONE;
    opcode_table[0x55].mnemonic = "castore"; opcode_table[0x55].operand_bytes = 0; opcode_table[0x55].op_type = OP_NONE;
    opcode_table[0x56].mnemonic = "sastore"; opcode_table[0x56].operand_bytes = 0; opcode_table[0x56].op_type = OP_NONE;

    // Stack operations
    opcode_table[0x57].mnemonic = "pop"; opcode_table[0x57].operand_bytes = 0; opcode_table[0x57].op_type = OP_NONE;
    opcode_table[0x58].mnemonic = "pop2"; opcode_table[0x58].operand_bytes = 0; opcode_table[0x58].op_type = OP_NONE;
    opcode_table[0x59].mnemonic = "dup"; opcode_table[0x59].operand_bytes = 0; opcode_table[0x59].op_type = OP_NONE;
    opcode_table[0x5a].mnemonic = "dup_x1"; opcode_table[0x5a].operand_bytes = 0; opcode_table[0x5a].op_type = OP_NONE;
    opcode_table[0x5b].mnemonic = "dup_x2"; opcode_table[0x5b].operand_bytes = 0; opcode_table[0x5b].op_type = OP_NONE;
    opcode_table[0x5c].mnemonic = "dup2"; opcode_table[0x5c].operand_bytes = 0; opcode_table[0x5c].op_type = OP_NONE;
    opcode_table[0x5d].mnemonic = "dup2_x1"; opcode_table[0x5d].operand_bytes = 0; opcode_table[0x5d].op_type = OP_NONE;
    opcode_table[0x5e].mnemonic = "dup2_x2"; opcode_table[0x5e].operand_bytes = 0; opcode_table[0x5e].op_type = OP_NONE;
    opcode_table[0x5f].mnemonic = "swap"; opcode_table[0x5f].operand_bytes = 0; opcode_table[0x5f].op_type = OP_NONE;

    // Arithmetic
    opcode_table[0x60].mnemonic = "iadd"; opcode_table[0x60].operand_bytes = 0; opcode_table[0x60].op_type = OP_NONE;
    opcode_table[0x61].mnemonic = "ladd"; opcode_table[0x61].operand_bytes = 0; opcode_table[0x61].op_type = OP_NONE;
    opcode_table[0x62].mnemonic = "fadd"; opcode_table[0x62].operand_bytes = 0; opcode_table[0x62].op_type = OP_NONE;
    opcode_table[0x63].mnemonic = "dadd"; opcode_table[0x63].operand_bytes = 0; opcode_table[0x63].op_type = OP_NONE;
    opcode_table[0x64].mnemonic = "isub"; opcode_table[0x64].operand_bytes = 0; opcode_table[0x64].op_type = OP_NONE;
    opcode_table[0x65].mnemonic = "lsub"; opcode_table[0x65].operand_bytes = 0; opcode_table[0x65].op_type = OP_NONE;
    opcode_table[0x66].mnemonic = "fsub"; opcode_table[0x66].operand_bytes = 0; opcode_table[0x66].op_type = OP_NONE;
    opcode_table[0x67].mnemonic = "dsub"; opcode_table[0x67].operand_bytes = 0; opcode_table[0x67].op_type = OP_NONE;
    opcode_table[0x68].mnemonic = "imul"; opcode_table[0x68].operand_bytes = 0; opcode_table[0x68].op_type = OP_NONE;
    opcode_table[0x69].mnemonic = "lmul"; opcode_table[0x69].operand_bytes = 0; opcode_table[0x69].op_type = OP_NONE;
    opcode_table[0x6a].mnemonic = "fmul"; opcode_table[0x6a].operand_bytes = 0; opcode_table[0x6a].op_type = OP_NONE;
    opcode_table[0x6b].mnemonic = "dmul"; opcode_table[0x6b].operand_bytes = 0; opcode_table[0x6b].op_type = OP_NONE;
    opcode_table[0x6c].mnemonic = "idiv"; opcode_table[0x6c].operand_bytes = 0; opcode_table[0x6c].op_type = OP_NONE;
    opcode_table[0x6d].mnemonic = "ldiv"; opcode_table[0x6d].operand_bytes = 0; opcode_table[0x6d].op_type = OP_NONE;
    opcode_table[0x6e].mnemonic = "fdiv"; opcode_table[0x6e].operand_bytes = 0; opcode_table[0x6e].op_type = OP_NONE;
    opcode_table[0x6f].mnemonic = "ddiv"; opcode_table[0x6f].operand_bytes = 0; opcode_table[0x6f].op_type = OP_NONE;
    opcode_table[0x70].mnemonic = "irem"; opcode_table[0x70].operand_bytes = 0; opcode_table[0x70].op_type = OP_NONE;
    opcode_table[0x71].mnemonic = "lrem"; opcode_table[0x71].operand_bytes = 0; opcode_table[0x71].op_type = OP_NONE;
    opcode_table[0x72].mnemonic = "frem"; opcode_table[0x72].operand_bytes = 0; opcode_table[0x72].op_type = OP_NONE;
    opcode_table[0x73].mnemonic = "drem"; opcode_table[0x73].operand_bytes = 0; opcode_table[0x73].op_type = OP_NONE;
    opcode_table[0x74].mnemonic = "ineg"; opcode_table[0x74].operand_bytes = 0; opcode_table[0x74].op_type = OP_NONE;
    opcode_table[0x75].mnemonic = "lneg"; opcode_table[0x75].operand_bytes = 0; opcode_table[0x75].op_type = OP_NONE;
    opcode_table[0x76].mnemonic = "fneg"; opcode_table[0x76].operand_bytes = 0; opcode_table[0x76].op_type = OP_NONE;
    opcode_table[0x77].mnemonic = "dneg"; opcode_table[0x77].operand_bytes = 0; opcode_table[0x77].op_type = OP_NONE;
    opcode_table[0x78].mnemonic = "ishl"; opcode_table[0x78].operand_bytes = 0; opcode_table[0x78].op_type = OP_NONE;
    opcode_table[0x79].mnemonic = "lshl"; opcode_table[0x79].operand_bytes = 0; opcode_table[0x79].op_type = OP_NONE;
    opcode_table[0x7a].mnemonic = "ishr"; opcode_table[0x7a].operand_bytes = 0; opcode_table[0x7a].op_type = OP_NONE;
    opcode_table[0x7b].mnemonic = "lshr"; opcode_table[0x7b].operand_bytes = 0; opcode_table[0x7b].op_type = OP_NONE;
    opcode_table[0x7c].mnemonic = "iushr"; opcode_table[0x7c].operand_bytes = 0; opcode_table[0x7c].op_type = OP_NONE;
    opcode_table[0x7d].mnemonic = "lushr"; opcode_table[0x7d].operand_bytes = 0; opcode_table[0x7d].op_type = OP_NONE;
    opcode_table[0x7e].mnemonic = "iand"; opcode_table[0x7e].operand_bytes = 0; opcode_table[0x7e].op_type = OP_NONE;
    opcode_table[0x7f].mnemonic = "land"; opcode_table[0x7f].operand_bytes = 0; opcode_table[0x7f].op_type = OP_NONE;
    opcode_table[0x80].mnemonic = "ior"; opcode_table[0x80].operand_bytes = 0; opcode_table[0x80].op_type = OP_NONE;
    opcode_table[0x81].mnemonic = "lor"; opcode_table[0x81].operand_bytes = 0; opcode_table[0x81].op_type = OP_NONE;
    opcode_table[0x82].mnemonic = "ixor"; opcode_table[0x82].operand_bytes = 0; opcode_table[0x82].op_type = OP_NONE;
    opcode_table[0x83].mnemonic = "lxor"; opcode_table[0x83].operand_bytes = 0; opcode_table[0x83].op_type = OP_NONE;
    opcode_table[0x84].mnemonic = "iinc"; opcode_table[0x84].operand_bytes = 2; opcode_table[0x84].op_type = OP_IINC; // Special: 1 byte index, 1 byte constant

    // Conversions
    opcode_table[0x85].mnemonic = "i2l"; opcode_table[0x85].operand_bytes = 0; opcode_table[0x85].op_type = OP_NONE;
    opcode_table[0x86].mnemonic = "i2f"; opcode_table[0x86].operand_bytes = 0; opcode_table[0x86].op_type = OP_NONE;
    opcode_table[0x87].mnemonic = "i2d"; opcode_table[0x87].operand_bytes = 0; opcode_table[0x87].op_type = OP_NONE;
    opcode_table[0x88].mnemonic = "l2i"; opcode_table[0x88].operand_bytes = 0; opcode_table[0x88].op_type = OP_NONE;
    opcode_table[0x89].mnemonic = "l2f"; opcode_table[0x89].operand_bytes = 0; opcode_table[0x89].op_type = OP_NONE;
    opcode_table[0x8a].mnemonic = "l2d"; opcode_table[0x8a].operand_bytes = 0; opcode_table[0x8a].op_type = OP_NONE;
    opcode_table[0x8b].mnemonic = "f2i"; opcode_table[0x8b].operand_bytes = 0; opcode_table[0x8b].op_type = OP_NONE;
    opcode_table[0x8c].mnemonic = "f2l"; opcode_table[0x8c].operand_bytes = 0; opcode_table[0x8c].op_type = OP_NONE;
    opcode_table[0x8d].mnemonic = "f2d"; opcode_table[0x8d].operand_bytes = 0; opcode_table[0x8d].op_type = OP_NONE;
    opcode_table[0x8e].mnemonic = "d2i"; opcode_table[0x8e].operand_bytes = 0; opcode_table[0x8e].op_type = OP_NONE;
    opcode_table[0x8f].mnemonic = "d2l"; opcode_table[0x8f].operand_bytes = 0; opcode_table[0x8f].op_type = OP_NONE;
    opcode_table[0x90].mnemonic = "d2f"; opcode_table[0x90].operand_bytes = 0; opcode_table[0x90].op_type = OP_NONE;
    opcode_table[0x91].mnemonic = "i2b"; opcode_table[0x91].operand_bytes = 0; opcode_table[0x91].op_type = OP_NONE;
    opcode_table[0x92].mnemonic = "i2c"; opcode_table[0x92].operand_bytes = 0; opcode_table[0x92].op_type = OP_NONE;
    opcode_table[0x93].mnemonic = "i2s"; opcode_table[0x93].operand_bytes = 0; opcode_table[0x93].op_type = OP_NONE;

    // Comparisons
    opcode_table[0x94].mnemonic = "lcmp"; opcode_table[0x94].operand_bytes = 0; opcode_table[0x94].op_type = OP_NONE;
    opcode_table[0x95].mnemonic = "fcmpl"; opcode_table[0x95].operand_bytes = 0; opcode_table[0x95].op_type = OP_NONE;
    opcode_table[0x96].mnemonic = "fcmpg"; opcode_table[0x96].operand_bytes = 0; opcode_table[0x96].op_type = OP_NONE;
    opcode_table[0x97].mnemonic = "dcmpl"; opcode_table[0x97].operand_bytes = 0; opcode_table[0x97].op_type = OP_NONE;
    opcode_table[0x98].mnemonic = "dcmpg"; opcode_table[0x98].operand_bytes = 0; opcode_table[0x98].op_type = OP_NONE;

    // Conditional branches
    opcode_table[0x99].mnemonic = "ifeq"; opcode_table[0x99].operand_bytes = 2; opcode_table[0x99].op_type = OP_BRANCH_SHORT;
    opcode_table[0x9a].mnemonic = "ifne"; opcode_table[0x9a].operand_bytes = 2; opcode_table[0x9a].op_type = OP_BRANCH_SHORT;
    opcode_table[0x9b].mnemonic = "iflt"; opcode_table[0x9b].operand_bytes = 2; opcode_table[0x9b].op_type = OP_BRANCH_SHORT;
    opcode_table[0x9c].mnemonic = "ifge"; opcode_table[0x9c].operand_bytes = 2; opcode_table[0x9c].op_type = OP_BRANCH_SHORT;
    opcode_table[0x9d].mnemonic = "ifgt"; opcode_table[0x9d].operand_bytes = 2; opcode_table[0x9d].op_type = OP_BRANCH_SHORT;
    opcode_table[0x9e].mnemonic = "ifle"; opcode_table[0x9e].operand_bytes = 2; opcode_table[0x9e].op_type = OP_BRANCH_SHORT;
    opcode_table[0x9f].mnemonic = "if_icmpeq"; opcode_table[0x9f].operand_bytes = 2; opcode_table[0x9f].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa0].mnemonic = "if_icmpne"; opcode_table[0xa0].operand_bytes = 2; opcode_table[0xa0].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa1].mnemonic = "if_icmplt"; opcode_table[0xa1].operand_bytes = 2; opcode_table[0xa1].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa2].mnemonic = "if_icmpge"; opcode_table[0xa2].operand_bytes = 2; opcode_table[0xa2].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa3].mnemonic = "if_icmpgt"; opcode_table[0xa3].operand_bytes = 2; opcode_table[0xa3].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa4].mnemonic = "if_icmple"; opcode_table[0xa4].operand_bytes = 2; opcode_table[0xa4].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa5].mnemonic = "if_acmpeq"; opcode_table[0xa5].operand_bytes = 2; opcode_table[0xa5].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa6].mnemonic = "if_acmpne"; opcode_table[0xa6].operand_bytes = 2; opcode_table[0xa6].op_type = OP_BRANCH_SHORT;

    // Jumps
    opcode_table[0xa7].mnemonic = "goto"; opcode_table[0xa7].operand_bytes = 2; opcode_table[0xa7].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa8].mnemonic = "jsr"; opcode_table[0xa8].operand_bytes = 2; opcode_table[0xa8].op_type = OP_BRANCH_SHORT;
    opcode_table[0xa9].mnemonic = "ret"; opcode_table[0xa9].operand_bytes = 1; opcode_table[0xa9].op_type = OP_LOCAL_INDEX_BYTE;

    // Switch statements (special handling for variable length)
    opcode_table[0xaa].mnemonic = "tableswitch"; opcode_table[0xaa].operand_bytes = -1; opcode_table[0xaa].op_type = OP_TABLESWITCH; // Operand bytes handled by function
    opcode_table[0xab].mnemonic = "lookupswitch"; opcode_table[0xab].operand_bytes = -1; opcode_table[0xab].op_type = OP_LOOKUPSWITCH; // Operand bytes handled by function

    // Returns
    opcode_table[0xac].mnemonic = "ireturn"; opcode_table[0xac].operand_bytes = 0; opcode_table[0xac].op_type = OP_NONE;
    opcode_table[0xad].mnemonic = "lreturn"; opcode_table[0xad].operand_bytes = 0; opcode_table[0xad].op_type = OP_NONE;
    opcode_table[0xae].mnemonic = "freturn"; opcode_table[0xae].operand_bytes = 0; opcode_table[0xae].op_type = OP_NONE;
    opcode_table[0xaf].mnemonic = "dreturn"; opcode_table[0xaf].operand_bytes = 0; opcode_table[0xaf].op_type = OP_NONE;
    opcode_table[0xb0].mnemonic = "areturn"; opcode_table[0xb0].operand_bytes = 0; opcode_table[0xb0].op_type = OP_NONE;
    opcode_table[0xb1].mnemonic = "return"; opcode_table[0xb1].operand_bytes = 0; opcode_table[0xb1].op_type = OP_NONE;

    // Field access
    opcode_table[0xb2].mnemonic = "getstatic"; opcode_table[0xb2].operand_bytes = 2; opcode_table[0xb2].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xb3].mnemonic = "putstatic"; opcode_table[0xb3].operand_bytes = 2; opcode_table[0xb3].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xb4].mnemonic = "getfield"; opcode_table[0xb4].operand_bytes = 2; opcode_table[0xb4].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xb5].mnemonic = "putfield"; opcode_table[0xb5].operand_bytes = 2; opcode_table[0xb5].op_type = OP_CP_INDEX_SHORT;

    // Method invocation
    opcode_table[0xb6].mnemonic = "invokevirtual"; opcode_table[0xb6].operand_bytes = 2; opcode_table[0xb6].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xb7].mnemonic = "invokespecial"; opcode_table[0xb7].operand_bytes = 2; opcode_table[0xb7].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xb8].mnemonic = "invokestatic"; opcode_table[0xb8].operand_bytes = 2; opcode_table[0xb8].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xb9].mnemonic = "invokeinterface"; opcode_table[0xb9].operand_bytes = 4; opcode_table[0xb9].op_type = OP_INVOKEINTERFACE; // Special: CP index, count, 0
    opcode_table[0xba].mnemonic = "invokedynamic"; opcode_table[0xba].operand_bytes = 4; opcode_table[0xba].op_type = OP_INVOKEDYNAMIC; // Special: CP index, 0, 0

    // Object creation and array creation
    opcode_table[0xbb].mnemonic = "new"; opcode_table[0xbb].operand_bytes = 2; opcode_table[0xbb].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xbc].mnemonic = "newarray"; opcode_table[0xbc].operand_bytes = 1; opcode_table[0xbc].op_type = OP_BYTE; // array type code
    opcode_table[0xbd].mnemonic = "anewarray"; opcode_table[0xbd].operand_bytes = 2; opcode_table[0xbd].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xbe].mnemonic = "arraylength"; opcode_table[0xbe].operand_bytes = 0; opcode_table[0xbe].op_type = OP_NONE;
    opcode_table[0xbf].mnemonic = "athrow"; opcode_table[0xbf].operand_bytes = 0; opcode_table[0xbf].op_type = OP_NONE;
    opcode_table[0xc0].mnemonic = "checkcast"; opcode_table[0xc0].operand_bytes = 2; opcode_table[0xc0].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xc1].mnemonic = "instanceof"; opcode_table[0xc1].operand_bytes = 2; opcode_table[0xc1].op_type = OP_CP_INDEX_SHORT;
    opcode_table[0xc2].mnemonic = "monitorenter"; opcode_table[0xc2].operand_bytes = 0; opcode_table[0xc2].op_type = OP_NONE;
    opcode_table[0xc3].mnemonic = "monitorexit"; opcode_table[0xc3].operand_bytes = 0; opcode_table[0xc3].op_type = OP_NONE;

    // Wide prefix
    opcode_table[0xc4].mnemonic = "wide"; opcode_table[0xc4].operand_bytes = 0; opcode_table[0xc4].op_type = OP_WIDE; // Special: modifies next instruction

    // Multidimensional array
    opcode_table[0xc5].mnemonic = "multianewarray"; opcode_table[0xc5].operand_bytes = 3; opcode_table[0xc5].op_type = OP_MULTIANEWARRAY; // Special: 2-byte CP index, 1-byte dimensions

    // Control
    opcode_table[0xc6].mnemonic = "ifnull"; opcode_table[0xc6].operand_bytes = 2; opcode_table[0xc6].op_type = OP_BRANCH_SHORT;
    opcode_table[0xc7].mnemonic = "ifnonnull"; opcode_table[0xc7].operand_bytes = 2; opcode_table[0xc7].op_type = OP_BRANCH_SHORT;
    opcode_table[0xc8].mnemonic = "goto_w"; opcode_table[0xc8].operand_bytes = 4; opcode_table[0xc8].op_type = OP_BRANCH_INT;
    opcode_table[0xc9].mnemonic = "jsr_w"; opcode_table[0xc9].operand_bytes = 4; opcode_table[0xc9].op_type = OP_BRANCH_INT;

    // Breakpoint (reserved for debuggers)
    opcode_table[0xca].mnemonic = "breakpoint"; opcode_table[0xca].operand_bytes = 0; opcode_table[0xca].op_type = OP_NONE;

    // Impdep (reserved for implementation-dependent operations)
    opcode_table[0xfe].mnemonic = "impdep1"; opcode_table[0xfe].operand_bytes = 0; opcode_table[0xfe].op_type = OP_NONE;
    opcode_table[0xff].mnemonic = "impdep2"; opcode_table[0xff].operand_bytes = 0; opcode_table[0xff].op_type = OP_NONE;

    initialized = 1;
}

static void print_indent(int level) {
    for (int i = 0; i < level; ++i) {
        printf("  ");
    }
}

static int16_t read_s16(const uint8_t *code, uint32_t *pc_ptr) {
    int16_t value = (int16_t)((code[*pc_ptr] << 8) | code[*pc_ptr + 1]);
    *pc_ptr += 2;
    return value;
}

static int32_t read_s32(const uint8_t *code, uint32_t *pc_ptr) {
    int32_t value = (int32_t)((code[*pc_ptr] << 24) | (code[*pc_ptr + 1] << 16) | (code[*pc_ptr + 2] << 8) | code[*pc_ptr + 3]);
    *pc_ptr += 4;
    return value;
}


// Main disassembly function
void disassemble_bytecode(const uint8_t *code, uint32_t code_length, const cp_info *constant_pool, int indent_level) {
    initialize_opcode_table();

    uint32_t pc = 0;
    uint8_t current_opcode;
    const opcode_info *info;
    int operand; // For 1-byte or 2-byte operands

    print_indent(indent_level);
    printf("        Code Bytes (Disassembly):\n");

    while (pc < code_length) {
        // Store current PC for branch targets
        uint32_t current_pc = pc;

        // Print PC offset
        print_indent(indent_level + 1);
        printf("%04X: ", current_pc);

        current_opcode = code[pc++];
        info = &opcode_table[current_opcode];

        // Print raw bytes for the instruction
        printf("%02X", current_opcode); // The opcode byte itself
        uint32_t start_operand_pc = pc; // Store for raw bytes printing later

        int extra_indent_for_operands = 0;

        // Handle 'wide' prefix first
        if (current_opcode == 0xc4) { // wide
            if (pc >= code_length) {
                printf(" (truncated) // %s\n", info->mnemonic);
                break;
            }
            uint8_t widened_opcode = code[pc++];
            printf(" %02X", widened_opcode);
            info = &opcode_table[widened_opcode];
            printf(" // %s", info->mnemonic);

            if (info->op_type == OP_LOCAL_INDEX_BYTE || widened_opcode == 0xa9) { // iload, aload, istore, astore, ret etc.
                if (pc + 1 >= code_length) { // Need 2 bytes for wide local index
                    printf(" (truncated) // %s\n", info->mnemonic);
                    break;
                }
                uint16_t index = (code[pc] << 8) | code[pc+1];
                printf(" %02X %02X", code[pc], code[pc+1]);
                pc += 2;
                printf(" %u", index);
            } else if (info->op_type == OP_IINC) {
                 if (pc + 3 >= code_length) { // Need 4 bytes for wide iinc (index, const)
                    printf(" (truncated) // %s\n", info->mnemonic);
                    break;
                }
                uint16_t index = (code[pc] << 8) | code[pc+1];
                int16_t const_val = (code[pc+2] << 8) | code[pc+3];
                printf(" %02X %02X %02X %02X", code[pc], code[pc+1], code[pc+2], code[pc+3]);
                pc += 4;
                printf(" %u by %d", index, const_val);
            } else {
                 fprintf(stderr, "Warning: 'wide' prefix with unhandled opcode 0x%02X.\n", widened_opcode);
                 // Fallback to skip remaining bytes of original instruction definition
                 for(int i = 0; i < info->operand_bytes; ++i) {
                     if (pc < code_length) {
                        printf(" %02X", code[pc++]);
                    } else {
                        printf(" (truncated)");
                        break;
                    }
                 }
            }
            printf("\n");
            continue; // Skip to next instruction
        }

        // Handle regular operands
        switch (info->op_type) {
            case OP_NONE:
                // No operands, just print mnemonic
                printf("       // %s\n", info->mnemonic);
                break;
            case OP_BYTE:
                if (pc >= code_length) { printf(" (truncated)\n"); break; }
                operand = code[pc++];
                printf(" %02X    // %s %d\n", (uint8_t)operand, info->mnemonic, operand);
                break;
            case OP_SHORT: 
                if (pc + 1 >= code_length) { printf(" (truncated)\n"); break; }
                operand = read_s16(code, &pc);
                printf(" %02X %02X // %s %d\n", code[current_pc+1], code[current_pc+2], info->mnemonic, operand);
                break;
            case OP_CP_INDEX_BYTE:
                if (pc >= code_length) { printf(" (truncated)\n"); break; }
                operand = code[pc++];
                printf(" %02X    // %s #%d // ", (uint8_t)operand, info->mnemonic, operand);
                if (operand > 0 && operand < constant_pool_count_global) {
                    print_constant_pool_entry(&constant_pool[operand-1], operand, constant_pool);
                } else {
                    printf("(Invalid CP index)");
                }
                printf("\n");
                break;
            case OP_CP_INDEX_SHORT: 
                if (pc + 1 >= code_length) { printf(" (truncated)\n"); break; }
                operand = read_s16(code, &pc);
                printf(" %02X %02X // %s #%d // ", code[current_pc+1], code[current_pc+2], info->mnemonic, operand);
                if (operand > 0 && operand < constant_pool_count_global) {
                     print_constant_pool_entry_value(&constant_pool[operand-1], constant_pool);
                } else {
                    printf("(Invalid CP index)");
                }
                printf("\n");
                break;
            case OP_LOCAL_INDEX_BYTE:
                if (pc >= code_length) { printf(" (truncated)\n"); break; }
                operand = code[pc++];
                printf(" %02X    // %s %d\n", (uint8_t)operand, info->mnemonic, operand);
                break;
            case OP_BRANCH_SHORT:
                if (pc + 1 >= code_length) { printf(" (truncated)\n"); break; }
                int16_t offset_short = read_s16(code, &pc);
                printf(" %02X %02X // %s %04X (+%d)\n", code[current_pc+1], code[current_pc+2], info->mnemonic, current_pc + offset_short, offset_short);
                break;
            case OP_BRANCH_INT:
                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                int32_t offset_int = read_s32(code, &pc);
                printf(" %02X %02X %02X %02X // %s %04X (+%d)\n", code[current_pc+1], code[current_pc+2], code[current_pc+3], code[current_pc+4], info->mnemonic, current_pc + offset_int, offset_int);
                break;
            case OP_IINC:
                if (pc + 1 >= code_length) { printf(" (truncated)\n"); break; }
                uint8_t index = code[pc++];
                int8_t const_val = (int8_t)code[pc++]; // Signed byte
                printf(" %02X %02X // %s %u by %d\n", index, (uint8_t)const_val, info->mnemonic, index, const_val);
                break;
            case OP_INVOKEINTERFACE: // invokeinterface
                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                uint16_t cp_index_invoke_int = read_s16(code, &pc); // Read index
                uint8_t count = code[pc++]; // Read count
                uint8_t zero_byte = code[pc++]; // Read 0 byte
                printf(" %02X %02X %02X %02X // %s #%u count %u 0x%02X // ",
                       code[current_pc+1], code[current_pc+2], count, zero_byte,
                       info->mnemonic, cp_index_invoke_int, count, zero_byte);
                if (cp_index_invoke_int > 0 && cp_index_invoke_int < constant_pool_count_global) {
                    print_constant_pool_entry_value(&constant_pool[cp_index_invoke_int-1], constant_pool);
                } else {
                    printf("(Invalid CP index)");
                }
                printf("\n");
                break;
            case OP_INVOKEDYNAMIC: // invokedynamic
                 if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                uint16_t cp_index_invoke_dyn = read_s16(code, &pc); // Read index
                uint8_t zero_byte1 = code[pc++]; // Read 0 byte
                uint8_t zero_byte2 = code[pc++]; // Read 0 byte
                printf(" %02X %02X %02X %02X // %s #%u 0x%02X 0x%02X // ",
                       code[current_pc+1], code[current_pc+2], zero_byte1, zero_byte2,
                       info->mnemonic, cp_index_invoke_dyn, zero_byte1, zero_byte2);
                if (cp_index_invoke_dyn > 0 && cp_index_invoke_dyn < constant_pool_count_global) {
                    print_constant_pool_entry_value(&constant_pool[cp_index_invoke_dyn-1], constant_pool);
                } else {
                    printf("(Invalid CP index)");
                }
                printf("\n");
                break;
            case OP_MULTIANEWARRAY: // multianewarray
                if (pc + 2 >= code_length) { printf(" (truncated)\n"); break; }
                uint16_t cp_index_multi = read_s16(code, &pc);
                uint8_t dimensions = code[pc++];
                printf(" %02X %02X %02X // %s #%u dim %u // ",
                       code[current_pc+1], code[current_pc+2], dimensions,
                       info->mnemonic, cp_index_multi, dimensions);
                if (cp_index_multi > 0 && cp_index_multi < constant_pool_count_global) {
                    print_constant_pool_entry_value(&constant_pool[cp_index_multi-1], constant_pool);
                } else {
                    printf("(Invalid CP index)");
                }
                printf("\n");
                break;
            case OP_TABLESWITCH: // tableswitch
            {
                // Align to 4-byte boundary
                uint32_t padding = (4 - (current_pc + 1) % 4) % 4;
                pc += padding;
                printf(" (%u padding bytes)", padding);

                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                int32_t default_offset = read_s32(code, &pc);
                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                int32_t low_value = read_s32(code, &pc);
                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                int32_t high_value = read_s32(code, &pc);

                printf(" // %s default:%04X (target %04X), low:%d, high:%d\n",
                       info->mnemonic, current_pc + default_offset, current_pc + default_offset, low_value, high_value);
                print_indent(indent_level + 2);
                printf("         Jump offsets:\n");

                for (int i = 0; i <= (high_value - low_value); ++i) {
                    if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                    int32_t jump_offset = read_s32(code, &pc);
                    print_indent(indent_level + 3);
                    printf("           %d: %04X (target %04X)\n", low_value + i, current_pc + jump_offset, current_pc + jump_offset);
                }
                break;
            }
            case OP_LOOKUPSWITCH:
            {
                // Align to 4-byte boundary
                uint32_t padding = (4 - (current_pc + 1) % 4) % 4;
                pc += padding;
                printf(" (%u padding bytes)", padding);

                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                int32_t default_offset = read_s32(code, &pc);
                if (pc + 3 >= code_length) { printf(" (truncated)\n"); break; }
                int32_t npairs = read_s32(code, &pc);

                printf(" // %s default:%04X (target %04X), npairs:%d\n",
                       info->mnemonic, current_pc + default_offset, current_pc + default_offset, npairs);
                print_indent(indent_level + 2);
                printf("         Match-Offset pairs:\n");

                for (int i = 0; i < npairs; ++i) {
                    if (pc + 7 >= code_length) { printf(" (truncated)\n"); break; } // match + offset
                    int32_t match = read_s32(code, &pc);
                    int32_t offset = read_s32(code, &pc);
                    print_indent(indent_level + 3);
                    printf("           %d: %04X (target %04X)\n", match, current_pc + offset, current_pc + offset);
                }
                break;
            }
            default: // Should not happen if all types are handled
                fprintf(stderr, "Error: Unhandled operand type for opcode 0x%02X (%s).\n", current_opcode, info->mnemonic);
                // Print raw bytes for remaining operands defined by the opcode_info
                for (int i = 0; i < info->operand_bytes; ++i) {
                    if (pc < code_length) {
                        printf(" %02X", code[pc++]);
                    } else {
                        printf(" (truncated)");
                        break;
                    }
                }
                printf(" // %s (unhandled operands)\n", info->mnemonic);
                break;
        }
    }
}