#include <stdio.h>
#include <inttypes.h>

#include <mach/mach_vm.h>

#include "memaccess.h"

static char *name_for_tag(int tag)
{
    switch (tag) {
    case 0: return "0";
    case VM_MEMORY_MALLOC: return "malloc";
    case VM_MEMORY_MALLOC_SMALL: return "malloc small";
    case VM_MEMORY_MALLOC_LARGE: return "malloc large";
    case VM_MEMORY_MALLOC_HUGE: return "malloc huge";
    case VM_MEMORY_SBRK: return "sbrk";
    case VM_MEMORY_REALLOC: return "malloc realloc";
    case VM_MEMORY_MALLOC_TINY: return "malloc tiny";
    case VM_MEMORY_MALLOC_LARGE_REUSABLE: return "malloc large-reusable";
    case VM_MEMORY_MALLOC_LARGE_REUSED: return "malloc large-reused";
    case VM_MEMORY_ANALYSIS_TOOL: return "Performance tool data";
    case VM_MEMORY_MALLOC_NANO: return "malloc nano";
    case 12: return "Unknown tag 12";
    case 13: return "Unknown tag 13";
    case 14: return "Unknown tag 14";
    case 15: return "Unknown tag 15";
    case 16: return "Unknown tag 16";
    case 17: return "Unknown tag 17";
    case 18: return "Unknown tag 18";
    case 19: return "Unknown tag 19";
    case VM_MEMORY_MACH_MSG: return "Mach message";
    case VM_MEMORY_IOKIT: return "IOKit";
    case 22: return "Unknown tag 22";
    case 23: return "Unknown tag 23";
    case 24: return "Unknown tag 24";
    case 25: return "Unknown tag 25";
    case 26: return "Unknown tag 26";
    case 27: return "Unknown tag 27";
    case 28: return "Unknown tag 28";
    case 29: return "Unknown tag 29";
    case VM_MEMORY_STACK: return "stack";
    case VM_MEMORY_GUARD: return "guard";
    case VM_MEMORY_SHARED_PMAP: return "shared PMAP";
    case VM_MEMORY_DYLIB: return "shared dylib";
    case VM_MEMORY_OBJC_DISPATCHERS: return "OBJC dispatchers";
    case VM_MEMORY_UNSHARED_PMAP: return "unshared PMAP";
    case 36: return "Unknown tag 36";
    case 37: return "Unknown tag 37";
    case 38: return "Unknown tag 38";
    case 39: return "Unknown tag 39";
    case VM_MEMORY_APPKIT: return "AppKit";
    case VM_MEMORY_FOUNDATION: return "Foundation";
    case VM_MEMORY_COREGRAPHICS: return "CoreGraphics";
    case VM_MEMORY_CORESERVICES: return "CoreServices";
    case VM_MEMORY_JAVA: return "Java";
    case VM_MEMORY_COREDATA: return "CoreData";
    case VM_MEMORY_COREDATA_OBJECTIDS: return "CoreData ObjectIds";
    case 47: return "Unknown tag 47";
    case 48: return "Unknown tag 48";
    case 49: return "Unknown tag 49";
    case VM_MEMORY_ATS: return "ATS (font support)";
    case VM_MEMORY_LAYERKIT: return "LAYERKIT";
    case VM_MEMORY_CGIMAGE: return "CGIMAGE";
    case VM_MEMORY_TCMALLOC: return "TCMALLOC";
    case VM_MEMORY_COREGRAPHICS_DATA: return "CoreGraphics Data";
    case VM_MEMORY_COREGRAPHICS_SHARED: return "CoreGraphics Shared";
    case VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS: return "CoreGraphics FrameBuffers";
    case VM_MEMORY_COREGRAPHICS_BACKINGSTORES: return "CoreGraphics BackingStores";
    case 58: return "Unknown tag 58";
    case 59: return "Unknown tag 59";
    case VM_MEMORY_DYLD: return "Dynamic Loader";
    case VM_MEMORY_DYLD_MALLOC: return "Dynamic Loader malloc";
    case VM_MEMORY_SQLITE: return "SQLITE";
    case VM_MEMORY_JAVASCRIPT_CORE: return "JavaScript Core";
    case VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR: return "JavaScript JIT Executable Allocator";
    case VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE: return "JavaScript JIT Register File";
    case VM_MEMORY_GLSL: return "GLSL";
    case VM_MEMORY_OPENCL: return "OpenCL";
    case VM_MEMORY_COREIMAGE: return "CoreImage";
    case VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS: return "WebCore Purgable Buffers";
    case VM_MEMORY_IMAGEIO: return "ImageIO";
    case VM_MEMORY_COREPROFILE: return "CoreProfile";
    case VM_MEMORY_ASSETSD: return "AssetsD";
    case VM_MEMORY_OS_ALLOC_ONCE: return "OS Alloc Once";
    case VM_MEMORY_LIBDISPATCH: return "LibDispatch";
    case VM_MEMORY_ACCELERATE: return "Accelerate";
    case VM_MEMORY_COREUI: return "CoreUI";

    case VM_MEMORY_APPLICATION_SPECIFIC_1: return "Application Specific 1";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 1: return "Application Specific 2";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 2: return "Application Specific 3";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 3: return "Application Specific 4";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 4: return "Application Specific 5";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 5: return "Application Specific 6";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 6: return "Application Specific 7";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 7: return "Application Specific 8";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 8: return "Application Specific 9";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 9: return "Application Specific 10";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 10: return "Application Specific 11";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 11: return "Application Specific 12";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 12: return "Application Specific 13";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 13: return "Application Specific 14";
    case VM_MEMORY_APPLICATION_SPECIFIC_1 + 14: return "Application Specific 15";
    case VM_MEMORY_APPLICATION_SPECIFIC_16: return "Application Specific 16";

    default: return "";
    }
}

response_t *get_next_memory_region(process_handle_t handle, memory_address_t address, bool *region_available, memory_region_t *memory_region) {
    response_t *response = response_create();

    kern_return_t kret;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count = 0;
    mach_vm_address_t addr = address;
    mach_vm_size_t size = 0;
    uint32_t depth = 0;
    *region_available = false;

    for (;;) {
        info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kret = mach_vm_region_recurse(handle, &addr, &size, &depth, (vm_region_recurse_info_t)&info, &info_count);

        if (kret == KERN_INVALID_ADDRESS) {
            break;
        }

        if (kret != KERN_SUCCESS) {
            response_set_fatal_from_kret(response, kret);
            return response;
        }

        if(info.is_submap) {
            depth += 1;
            continue;
        }

	// Incomprehensible bug wherein the wrong block is returned for the last (past) address of the the region
	if (addr + size <= address)
	{
		addr = address + 1;
		continue;
	}

	*region_available = true;
	memory_region->start_address = addr;
	memory_region->length = size;
	memory_region->access = a_none;
	if (info.protection & VM_PROT_READ)  memory_region->access += a_readable;
	if (info.protection & VM_PROT_WRITE) memory_region->access += a_writable;
	if (info.protection & VM_PROT_EXECUTE)  memory_region->access += a_executable;
	memory_region->kind = name_for_tag(info.user_tag);
	break;

        addr += size;
    }

    return response;
}

response_t *get_next_readable_memory_region(process_handle_t handle,
        memory_address_t address, bool *region_available,
        memory_region_t *memory_region) {
    response_t *response = response_create();

    kern_return_t kret;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count = 0;
    mach_vm_address_t addr = address;
    mach_vm_size_t size = 0;
    uint32_t depth = 0;
    *region_available = false;

abort();
    for (;;) {
        info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kret = mach_vm_region_recurse(handle, &addr, &size, &depth, (vm_region_recurse_info_t)&info, &info_count);

        if (kret == KERN_INVALID_ADDRESS) {
            break;
        }

        if (kret != KERN_SUCCESS) {
            response_set_fatal_from_kret(response, kret);
            return response;
        }

        if(info.is_submap) {
            depth += 1;
            continue;
        }

        if ((info.protection & VM_PROT_READ) != VM_PROT_READ) {
            if (*region_available) {
                return response;
            }

            char *description = NULL;
            asprintf(
                &description,
                "memory unreadable: %llx-%llx",
                addr,
                addr + size - 1
            );
            response_add_soft_error(response, -1, description);
        } else {
            if (!(*region_available)) {

                // Sometimes a previous region is returned that doesn't contain,
                // address. This would lead to an infinite loop while using
                // the regions, getting every time the same one. To avoid this
                // we ask for the region 1 byte after address.
                if (addr + size <= address) {
                    char *description = NULL;
                    char *format = "wrong region obtained, expected it to "
                        "contain %" PRIxPTR ", but got: %" PRIxPTR "-%"
                        PRIxPTR;
                    asprintf(
                        &description,
                        format,
                        address,
                        addr,
                        addr + size - 1
                    );
                    response_add_soft_error(response, -1, description);

                    addr = address + 1;
                    continue;
                }

                *region_available = true;
                memory_region->start_address = addr;
                memory_region->length = size;
            } else {
                memory_address_t limit_address = memory_region->start_address +
                    memory_region->length;

                if (limit_address < addr) {
                    return response;
                }

                mach_vm_size_t overlaped_bytes = limit_address - addr;
                memory_region->length += size - overlaped_bytes;
            }
        }

        addr += size;
    }

    return response;
}

response_t *copy_process_memory(process_handle_t handle,
        memory_address_t start_address, size_t bytes_to_read, void *buffer,
        size_t *bytes_read) {

    response_t *response = response_create();

    mach_vm_size_t read;
    kern_return_t kret = mach_vm_read_overwrite(handle, start_address,
            bytes_to_read, (mach_vm_address_t) buffer, &read);

    if (kret != KERN_SUCCESS) {
        response_set_fatal_from_kret(response, kret);
        return response;
    }

    *bytes_read = read;
    return response;
}

