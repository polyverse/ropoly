#define PACKAGE 1
#define PACKAGE_VERSION 1
#include "dis-asm.h"

typedef void *DisAsmPtr;
typedef unsigned long DisAsmLen;

typedef struct DisAsmPrintBuffer {
	int	index;
	char	data[1024];
} DisAsmPrintBufferType, *DisAsmPrintBufferPtr;

typedef struct DisAsmInfo {
	disassemble_info info;
	DisAsmPrintBufferType disAsmPrintBuffer;
	DisAsmPtr start;
	DisAsmPtr end;
} DisAsmInfoType, *DisAsmInfoPtr;

extern DisAsmPtr DisAsmSafeStartAddress(void);
extern DisAsmInfoPtr DisAsmInfoInit(DisAsmPtr start, DisAsmLen length);
extern unsigned char DisAsmAccessByte(DisAsmInfoPtr disAsmInfoPtr, DisAsmPtr pc);
extern DisAsmLen DisAsmDecodeInstruction(DisAsmInfoPtr disAsmInfoPtr, DisAsmPtr pc);
extern void DisAsmInfoFree(DisAsmInfoPtr disAsmInfoPtr);
extern DisAsmPtr DisAsmSafeEndAddress(void);
