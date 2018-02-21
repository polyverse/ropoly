#include <assert.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include "disasm.h"

static void DisAsmPrintAddress(bfd_vma addr, struct disassemble_info *info)
{
        info->fprintf_func(info->stream, "%p", (void *) addr);
} // DisAsmPrintAddress()

static int DisAsmPrintf(void *b, const char *fmt, ...)
{
	DisAsmPrintBufferPtr pbPtr = (DisAsmPrintBufferPtr) b;

	va_list arglist;
	va_start(arglist, fmt);
	int result = vsprintf(pbPtr->data + pbPtr->index, fmt, arglist);
	assert(pbPtr->index + result < sizeof(pbPtr->data));
	pbPtr->index += result;
	va_end(arglist);

	return result;
}

DisAsmInfoPtr DisAsmInfoInit(DisAsmPtr start, DisAsmPtr end)
{
	DisAsmInfoPtr disAsmInfoPtr = calloc(1, sizeof(*disAsmInfoPtr));

        disAsmInfoPtr->info.flavour                   = bfd_target_unknown_flavour;
        disAsmInfoPtr->info.arch                      = bfd_arch_i386;
        disAsmInfoPtr->info.mach                      = bfd_mach_x86_64_intel_syntax;
        disAsmInfoPtr->info.endian                    = BFD_ENDIAN_LITTLE;
        disAsmInfoPtr->info.octets_per_byte           = 1;
        disAsmInfoPtr->info.fprintf_func              = DisAsmPrintf;
        disAsmInfoPtr->info.stream                    = &disAsmInfoPtr->disAsmPrintBuffer;
        disAsmInfoPtr->info.read_memory_func          = buffer_read_memory;
        disAsmInfoPtr->info.memory_error_func         = perror_memory;
        disAsmInfoPtr->info.print_address_func        = DisAsmPrintAddress;
        disAsmInfoPtr->info.symbol_at_address_func    = generic_symbol_at_address;
        disAsmInfoPtr->info.symbol_is_valid           = generic_symbol_is_valid;
        disAsmInfoPtr->info.display_endian            = BFD_ENDIAN_LITTLE;
        disAsmInfoPtr->info.buffer_vma                = (unsigned long) start;
        disAsmInfoPtr->info.buffer_length             = end - start + 1;
        disAsmInfoPtr->info.buffer                    = start;
	
	return disAsmInfoPtr;
} // DisAsmInfoInit()

DisAsmInfoPtr DisAsmInfoInitBytes(DisAsmPtr start, DisAsmPtr end, void *b)
{
	DisAsmInfoPtr disAsmInfoPtr = calloc(1, sizeof(*disAsmInfoPtr));

        disAsmInfoPtr->info.flavour                   = bfd_target_unknown_flavour;
        disAsmInfoPtr->info.arch                      = bfd_arch_i386;
        disAsmInfoPtr->info.mach                      = bfd_mach_x86_64_intel_syntax;
        disAsmInfoPtr->info.endian                    = BFD_ENDIAN_LITTLE;
        disAsmInfoPtr->info.octets_per_byte           = 1;
        disAsmInfoPtr->info.fprintf_func              = DisAsmPrintf;
        disAsmInfoPtr->info.stream                    = &disAsmInfoPtr->disAsmPrintBuffer;
        disAsmInfoPtr->info.read_memory_func          = buffer_read_memory;
        disAsmInfoPtr->info.memory_error_func         = perror_memory;
        disAsmInfoPtr->info.print_address_func        = DisAsmPrintAddress;
        disAsmInfoPtr->info.symbol_at_address_func    = generic_symbol_at_address;
        disAsmInfoPtr->info.symbol_is_valid           = generic_symbol_is_valid;
        disAsmInfoPtr->info.display_endian            = BFD_ENDIAN_LITTLE;
        disAsmInfoPtr->info.buffer_vma                = (unsigned long) start;
        disAsmInfoPtr->info.buffer_length             = end - start + 1;
        disAsmInfoPtr->info.buffer                    = b;
	
	return disAsmInfoPtr;
} // DisAsmInfoInitBytes()

DisAsmLen DisAsmDecodeInstruction(DisAsmInfoType *disAsmInfoPtr, DisAsmPtr pc)
{
	disAsmInfoPtr->disAsmPrintBuffer.index = 0;

        //DisAsmPrintf(disAsmInfoPtr->info.stream, "%p ", pc);

	int count = (int) print_insn_i386((unsigned long) pc, &disAsmInfoPtr->info);
	assert(count != 0);

        //DisAsmPrintf(disAsmInfoPtr->info.stream, "\n");

        return count;
} // DisAsmDecodeInstruction()

void DisAsmInfoFree(DisAsmInfoPtr disAsmInfoPtr)
{
	free(disAsmInfoPtr);
} // DisAsmInfoFree()
