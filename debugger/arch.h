#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

#define SZ 2
#define FEATURE_STR "l<target version=\"1.0\"><architecture>z80</architecture></target>"

static uint8_t break_instr[] = {0xf0, 0x01, 0xf0, 0xe7};

#define PC_REGISTER 15
#define EXTRA_NUM 25
#define EXTRA_REG 16
#define EXTRA_SIZE 4

#endif /* ARCH_H */
