#define _FILE_OFFSET_BITS 64
// Includes
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <limits.h>
#include <fcntl.h>

#include "main.h"

typedef struct segment_item_S {
    void*       segment_ptr;    // pointer to mapped segment
    __uint64_t  segment_size;    // size of mapped segment in memory
} segment_item_T;

typedef struct bin_info_table_S {
    Elf64_Addr  entrypoint;         // this maybe zero --> PIE
    int         elf_fd;             // file stream of the ELF file
    __uint64_t  elf_file_size;      // size of the complete efi file
    Elf64_Ehdr* elf_header;         // pointer to allocated memory storing the elf header
    Elf64_Phdr* prog_header_table;  // pointer to allocated memory storing the program header table
    int         allocd_segs_len;    // len of allocd_segs array
    segment_item_T* allocd_segments;  // array of pointers to segment_item_T structs
    void*       initial_user_stack; // points to the beginning (lowest address) of the memory of the stack
    void*       initial_user_stack_sp;  // points to the beginning (highest address) of the initial user stack
    Elf64_Addr  last_mapping_size;  // holds the last mapping size --> for calculating the next mapping
    int         sys_page_size;      // systems page size as returned by getpagesize()
    Elf64_Xword elf_page_size;      // page size specified in the elf program headers
    Elf64_Addr  phdr_table_vaddr;   // virtual address of the process header loaded into memory relative to the first loaded segment

    /* PIE vars */
    bool        isPIE;              // bool to indicate whether the loaded elf is a PIE or not
    Elf64_Addr  load_bias;          // the address at which the program begins to get mapped/loaded
    Elf64_Xword total_mapping_size; // total virtual mapping size of the program image
    Elf64_Addr  initial_user_stack_PIC; // points to the user stack relative to the PIE-base
} bin_info_table_T;

/**
 * Function for seeking with offsets of greater length than `long', namely up to an offsets of type `Elf64_Off'
 *
 * @param fd File descriptor for file to seek in
 * @param offset Offset to seek within the file
 * @param whence Position to begin seeking in the file
 * @return Returns 0 if successful, an errno code if not successful
 */
long long int safe_lseek(const int fd, Elf64_Off offset, int whence) {
    STANDARD_FUNCTION_START

    // First have this lseek block so we can use the whence as a starting point
    if (offset > LONG_MAX) {
        if (0 > lseek(fd, LONG_MAX, whence)) JMP_W_ERROR("Initial lseek failed", ret);
        offset -= LONG_MAX;
        whence = SEEK_CUR;
    }

    // Next, while the offset is still greater than LONG_MAX, seek with LONG_MAX until its less or equal than LONG_MAX
    while (offset > LONG_MAX) {
        if (0 > lseek(fd, LONG_MAX, whence)) JMP_W_ERROR("Iterative lseek failed", ret);
        offset -= LONG_MAX;
    }

    // Finally, the offset the less or equal to LONG_MAX so we seek with the offset that is left (cast to a long)
    if (0 > lseek(fd, (long)offset, whence)) JMP_W_ERROR("Closing lseek failed", ret);

    // Just return -errno in any case as we don't have any other instructions that would need a retval themselves
    STANDARD_FUNCTION_RETURN(-errno);
}

/**
 * This functions reads in nbytes from fd and stores them in buf using the kernel function `read`.
 * Important: The current file position is not altered! The bytes read are not returned!
 * It also checks the result of the read and throws an error if necessary.
 * (Packing this into its own functions to avoid code duplication.)
 *
 * @param fd File descriptor
 * @param buf Buffer to write things into
 * @param nbytes Number of bytes to read from the file
 * @return Returns 0 if successful, an errno code if not successful
 */
int safe_read(const int fd, void* buf, const size_t nbytes) {
    STANDARD_FUNCTION_START;

    const long long int cur_fpos = safe_lseek(fd, 0, SEEK_CUR);  // get the current file position to restore it later
    const ssize_t read_result = read(fd, buf, nbytes);
    if (!read_result) JMP_W_CERROR("Unexpectedly reached EOF", ret);
    if (-1 == read_result || nbytes != (Elf64_Xword)read_result)
        JMP_W_ERROR("Failed to read segment from file", ret);
    safe_lseek(fd, cur_fpos, SEEK_SET);

    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for extracting the program- and section- header table from the elf file given the offset, its size and the amount of entries
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 * @param offset Offset in elf file where the header table entries are stored
 * @param hdr_t_size Size of the table
 * @param hdr_t_ent Amount of entries in the table
 * @param hdr_t_ptr Address to pointer to location to store the allocated space for the header table
 * @return Returns 0 if successful, an errno code if not successful
 */
int get_header_table(
    const bin_info_table_T* bin_infos,
    const Elf64_Off offset,
    const Elf64_Half hdr_t_size,
    const Elf64_Half hdr_t_ent,
    void** hdr_t_ptr  /* we use a void* here cause we have to except multiple different pointer types */
    ) {
    STANDARD_FUNCTION_START;

    // define whether we handle a section header or a program header
    const char* hdr_t_type = bin_infos->elf_header->e_phoff == offset ? "program" : "section";

    // check if the header table exits
    if (!offset) JMP_W_CERROR("%s header table size if 0", ret, hdr_t_type);
    // check if the header table offset does point to a valid location within the file
    if (offset > bin_infos->elf_file_size) JMP_W_CERROR("%s header table is beyond EOF", ret, hdr_t_type);

    // next get the header table
    if (0 > safe_lseek(bin_infos->elf_fd, offset, SEEK_SET))
        JMP_W_CERROR("Failed to seek in file", ret);

    const Elf64_Word phdrtsize = hdr_t_size * hdr_t_ent;
    void* hdr_buffer = calloc(1, phdrtsize);  // header table size
    if (NULL == hdr_buffer) {
        PRINT_CUSTOM_ERROR("Failed to allocate space for the %s-header-table-buffer", hdr_t_type);
        JMP_W_ERROR("Detailed allocation error", ret);
    }
    // read the header from the elf file and check, if we got all the bytes
    if (0 > safe_read(bin_infos->elf_fd, hdr_buffer, phdrtsize))
        JMP_W_CERROR("Failed to read the %s header table", ret, hdr_t_type);

    *hdr_t_ptr = hdr_buffer;
    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for opening and gathering information from the ELF binary, like checking its properties or
 * extracting header- and general information
 * Basically, every field is processed in the same order as they appear in the man-page --> `man elf`
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 * @param filename Path to and Filename of the ELF binary
 * @return Returns 0 if successful, an errno code if not successful
 */
int open_and_parse_elf(bin_info_table_T* bin_infos, const char* filename) {
    DEBUG("Parsing elf file");
    STANDARD_FUNCTION_START;

    // create a stdio file obj to the elf binary
    const int elf_fd = open(filename, O_RDONLY);
    if (-1 == elf_fd) JMP_W_ERROR("Failed to open the ELF binary", ret);
    bin_infos->elf_fd = elf_fd;
    const long long int elf_file_size = lseek(elf_fd, 0L, SEEK_END);
    if (0 > elf_file_size)
        JMP_W_CERROR("Failed to seek in file", ret);
    bin_infos->elf_file_size = elf_file_size;
    lseek(elf_fd, 0, SEEK_SET);  // set the file position to the beginning of the file

    // get the elf file header
    Elf64_Ehdr* elf_header = calloc(1, ELF_HEADER_SIZE);
    if (NULL == elf_header) JMP_W_CERROR("Failed to allocate space for the efi-header-buffer", ret);
    bin_infos->elf_header = elf_header;
    if (0 > safe_read(elf_fd, elf_header, ELF_HEADER_SIZE))
        JMP_W_CERROR("Failed to read the elf header", ret);

    /* Do consistency-checks to make sure it's an actual ELF file and also if we can process it */
    /* First do the checks on the e_ident field */
    // check the ELF magic number
    if (0 != memcmp(ELFMAG, elf_header->e_ident, SELFMAG)) JMP_W_CERROR("File is not an ELF file", ret);
    //check if the elf binary has the correct data architecture class (64-bit / for addresses, offsets, types, ...)
    if (ELFCLASS64 != elf_header->e_ident[EI_CLASS]) JMP_W_CERROR("Data architecture class is not 64-bit", ret);
    // check if the elf file is encoded in little endian
    if (ELFDATA2LSB != elf_header->e_ident[EI_DATA]) JMP_W_CERROR("ELF file is not encoded in little-endian", ret);
    // check if the elf file has the correct version
    if (EV_CURRENT != elf_header->e_ident[EI_VERSION] || EV_CURRENT != elf_header->e_version)
        JMP_W_CERROR("ELF File does not have the correct version", ret);
    // for now, we skip checking the EI_OSABI field

    // check if the elf file is indeed an executable file --> this is currently the only supported option
    if (ET_EXEC != elf_header->e_type && ET_DYN != elf_header->e_type)
        JMP_W_CERROR("EFI file is not an executable", ret);
    (ET_DYN == elf_header->e_type) ? (bin_infos->isPIE = true) : (bin_infos->isPIE = false);
    // check if the elf file contains the correct target instruction set architecture (64-bit / for instructions)
    if (EM_X86_64 != elf_header->e_machine) JMP_W_CERROR("EFI file has the wrong instruction set architecture", ret);

    // next get the entrypoint (as a virtual address) of the program
    bin_infos->entrypoint = elf_header->e_entry;  // this could be zero --> PIE

    // next get the program header table if it exists
    if (0 > get_header_table(bin_infos, elf_header->e_phoff, elf_header->e_phentsize,
                        elf_header->e_phnum, (void*)&bin_infos->prog_header_table)) {
        JMP_W_CERROR("Failed to load program header table", ret)
    }

    STANDARD_FUNCTION_RETURN(-ENOEXEC);
}

/**
 * Function for allocating or resizing an array by type_s * array_size
 *
 * @param array Pointer to array to allocate/resize
 * @param array_size Current size of the array
 * @param type_s Type that gets stored in the array, so we can calculate the new size
 * @return Returns 0 if successful, en errno code if not successful
 */
int realloc_array(void** array, const int* array_size, const int type_s) {
    STANDARD_FUNCTION_START;

    void* new_ptr = realloc(*array, type_s * *array_size);  // (re)alloc the array
    if (NULL == new_ptr) JMP_W_ERROR("Realloc failed", ret);    // check whether realloc failed or not
    *array = new_ptr;  // assign the new space to the array

    STANDARD_FUNCTION_RETURN(-ENOMEM)
}

/**
 * Function for calculating the total mapping size in virtual memory and the
 * biggest alignment/the biggest page size needed by the program.
 *
 * This function does maybe call itself recursively, if the page size changed
 * because of its calculations.
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 * @param default_page_sz The default page size to use for calculations
 */
void calc_phdr_vals(bin_info_table_T* bin_infos, const Elf64_Xword default_page_sz) {
    unsigned long min_addr = -1;
    unsigned long max_addr = 0;

    /* iterate over the program header table and calculate the total size and the maximum alignment needed */
    for (Elf64_Half i = 0; i<bin_infos->elf_header->e_phnum; i++) {
        const Elf64_Phdr phdr_entry = bin_infos->prog_header_table[i];  // get the next program header entry

        // update the global with the values from this iteration
        bin_infos->elf_page_size = MAX(bin_infos->elf_page_size, phdr_entry.p_align);
        min_addr = MIN(min_addr, ALIGN_TO_PAGE_DOWN(phdr_entry.p_vaddr, default_page_sz));
        max_addr = MAX(max_addr, phdr_entry.p_vaddr+phdr_entry.p_memsz);
    }
    // If the page size specified in the elf turns out to be not equal to the system page size, redo the calculations
    // This should always be true once --> there should never be more than one recursion!
    if (default_page_sz != bin_infos->elf_page_size) {
        DEBUG("Recursive call on function calc_phdr_vals!")
        calc_phdr_vals(bin_infos, bin_infos->elf_page_size);  // this should never result in another recursive call
        return;  // skip the below code
    }

    /* If the executable is a PIE, we also have to include the stack size in the total size */
    if (bin_infos->isPIE) {
        bin_infos->initial_user_stack_PIC = ALIGN_TO_PAGE_UP(max_addr, bin_infos->elf_page_size);
        bin_infos->total_mapping_size = ALIGN_TO_PAGE_UP(
            bin_infos->initial_user_stack_PIC + DEFAULT_STACK_SIZE, bin_infos->elf_page_size
            ) - min_addr;
    }
    else bin_infos->total_mapping_size = max_addr - min_addr;
}

/**
 * Function for loading the segment headers from the program header table into memory
 * and mapping all the relevant segments into the virtual address space of the new process
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 * @return Returns 0 if successful, an errno code if not successful
 */
int load_alloc_segments(bin_info_table_T* bin_infos) {
    STANDARD_FUNCTION_START;

    // calculate the biggest alignment and the total mapping size
    calc_phdr_vals(bin_infos, bin_infos->sys_page_size);

    bool first_pt_load = true;
    /* Begin of the mapped memory region */
    void* pa = nullptr;

    // iterate over the program header table and load the segments we need --> p_type=PT_LOAD
    for (Elf64_Half i = 0; i<bin_infos->elf_header->e_phnum; i++) {
        const Elf64_Phdr phdr_entry = bin_infos->prog_header_table[i];  // get the next program header entry

        /* When calculating the virtual address of the PHT, there is also the possibility for the PHT to
         * be described by a PHDR entry. In that case, the vaddr of the PHT is the vaddr of the PHDR entry. */
        if (PT_PHDR == phdr_entry.p_type &&
            phdr_entry.p_filesz == bin_infos->elf_header->e_phnum * bin_infos->elf_header->e_phentsize) {
            bin_infos->phdr_table_vaddr = phdr_entry.p_vaddr;
            continue;
        }
        if (PT_LOAD != phdr_entry.p_type) continue;  // skip all other segments

        /* Calculate the phdr-tables's (PHT) virtual address if there is no PHDR entry to describe it:
         * To do that we have to check if the virtual offset of the PHT does include the file offset of the PHT.
         * At the same time, the file offset of the PHT has to be within the memory of the segment the currently
         * loaded program header entry is pointing to.
         * Finally, the vaddr of the PHT is calculated by adding the difference between the file offset and the
         * virtual offset to the vaddr of the segment.
         */
        if (phdr_entry.p_offset <= bin_infos->elf_header->e_phoff &&
            bin_infos->elf_header->e_phoff < phdr_entry.p_offset + phdr_entry.p_filesz) {
            bin_infos->phdr_table_vaddr = phdr_entry.p_vaddr + (bin_infos->elf_header->e_phoff - phdr_entry.p_offset);
        }

        /*
         * If the executable is a (static) PIE, we allocate
         * the whole mapping at once. This is only possible
         * with PIEs. For detailed explanation see kernel function
         * This logic only runs once
         */
        if (first_pt_load && bin_infos->isPIE) {
            first_pt_load = false;  //

            // allocate space for the one pointer that will point to the mapped memory region
            if (NULL == (bin_infos->allocd_segments = calloc(1, sizeof(segment_item_T))))
                JMP_W_CERROR("Realloc failed on segment-mapping-address array", ret)

            /*
             * Map the whole virtual memory of the program image.
             * Here, 0 is used for the address to let mmap decide
             * which address to use. Whether this address was created
             * using ASLR or not depends on the implementation of mmap
             */
            // always set the protection of the mapping to write, cause we still have to write the segment data
            pa = mmap(nullptr, bin_infos->total_mapping_size, PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (MAP_FAILED != pa) {
                DEBUG("Successfully created memory mapping at address %p with size %lu", (void*)pa,
                    bin_infos->total_mapping_size);
                bin_infos->load_bias = (Elf64_Addr)pa + phdr_entry.p_vaddr;
                bin_infos->allocd_segments[0] = (segment_item_T){
                    .segment_ptr = pa, .segment_size = bin_infos->total_mapping_size
                };
                bin_infos->allocd_segs_len++;
            }
        }

        /* Next calculate the correct page start, page end, offset and the mapping-size
         * Calculate the start of the page in which the next segment resides:
         * page_start = ALIGN_TO_PAGE_DOWN(load_bias + vaddr, align)
         * --> so now page_start % align = 0
         *
         * Calculate the offset to where the segment will be written within the page and the size of the mapping:
         * page_offset = load_bias + p_vaddr - page_start
         * mapping_size = load_bias + page_offset + p_memsz
         *
         * Now the data of the segment can be written into the page at:
         * *(page_start + page_offset) = segment_data
         */
        const Elf64_Addr page_start = ALIGN_TO_PAGE_DOWN(bin_infos->load_bias + phdr_entry.p_vaddr, bin_infos->elf_page_size);
        const Elf64_Addr page_offset = bin_infos->load_bias + phdr_entry.p_vaddr - page_start;
        const Elf64_Addr mapping_size = page_offset + phdr_entry.p_memsz;
        bin_infos->last_mapping_size = mapping_size;

        /* If it's a normal executable, map every segment separately */
        if (!bin_infos->isPIE) {
            // if we found a loadable segment, allocate memory for the struct to store information about it
            bin_infos->allocd_segs_len++;  // increase the length index
            if (0 > realloc_array((void**)&bin_infos->allocd_segments, &bin_infos->allocd_segs_len, sizeof(segment_item_T)))
                JMP_W_CERROR("Realloc failed on segment-mapping-address array", ret)

            /* map the corresponding memory region */
            // always set the protection of the mapping to write, cause we still have to write the segment data
            pa = mmap((void*)page_start, mapping_size, PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

            if (MAP_FAILED != pa) {
                bin_infos->allocd_segments[bin_infos->allocd_segs_len-1] = (segment_item_T){
                    .segment_ptr = pa, .segment_size = mapping_size
                };
                if (pa != (void*)page_start)
                    JMP_W_CERROR("Failed to allocate memory for segment at correct address. \n"
                                 "Provided addr by mmap: %p vs. calculated addr from hdr: %p", ret, pa, (void*)page_start)

                DEBUG("Successfully created memory mapping at address %p with size %lu", (void*)pa, mapping_size);
                fflush(stdout);
            }
        }

        if (MAP_FAILED == pa) {
            PRINT_CUSTOM_ERROR("Failed to allocate memory at address %p with size %lu",
                bin_infos->allocd_segments[bin_infos->allocd_segs_len-1].segment_ptr, bin_infos->last_mapping_size);
            PRINT_ERROR("Error from mmap");
            goto ret;
        }

        // read in the segment data from the elf file and write it into the allocated memory of the segment
        if (0 > safe_lseek(bin_infos->elf_fd, phdr_entry.p_offset, SEEK_SET))
            JMP_W_CERROR("Failed to seek in file", ret);
        if (0 > safe_read(bin_infos->elf_fd, (void*)(page_start + page_offset), phdr_entry.p_filesz))
            JMP_W_CERROR("Failed to read segment from file", ret);
        // memset doesn't return an error, so we assume that this is always successful - idk :)
        memset_((void*)(page_start + page_offset + phdr_entry.p_filesz), 0x00, phdr_entry.p_memsz - phdr_entry.p_filesz);

        // next set the actual (correct) flags for this memory mapping by mapping the elf flags to the mmap flags
        const int mmap_seg_prot = (phdr_entry.p_flags & PF_X ? PROT_EXEC : 0) |
            (phdr_entry.p_flags & PF_W ? PROT_WRITE : 0) | (phdr_entry.p_flags & PF_R ? PROT_READ : 0);
        if (-1 == mprotect((void*)page_start, mapping_size, mmap_seg_prot)) JMP_W_ERROR("memprotect failed", ret);
    }

    // for non-PIEs, the load bias will be zero; for PIEs it will contain the address of the start of the image base
    bin_infos->entrypoint += bin_infos->load_bias;
    bin_infos->phdr_table_vaddr += bin_infos->load_bias;

    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for creating the initial user stack and filling it with argc, argv, envp and auxv
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 * @param argc The length of argv
 * @param argv The argv to pass to the new process
 * @return Returns 0 if successful, an errno code if not successful
 */
int create_initial_stack(bin_info_table_T* bin_infos, const int argc, char** argv) {
    STANDARD_FUNCTION_START;

    void* pa;
    constexpr int stack_flags = PROT_WRITE | PROT_READ;
    /*
     * If the executable is a PIE, the stack was already allocated
     * in memory, so we only have to calculate the beginning of it.
     * The result should be page-aligned.
     */
    if (bin_infos->isPIE) {
        pa = (void*) (ALIGN_TO_PAGE_UP(bin_infos->load_bias + bin_infos->initial_user_stack_PIC,
            bin_infos->elf_page_size));  // page-aligned start of stack
        // also set the correct permission for the stack
        if (-1 == mprotect(pa, DEFAULT_STACK_SIZE, stack_flags)) JMP_W_ERROR("memprotect failed", ret);
    }
    else {
        /*
         * If the executable is not a PIE, calculate the beginning of the next page
         * starting from the last memory mapping. By doing that here, we have some code
         * duplication but this is inevitable
         */
        Elf64_Addr new_page_start = (Elf64_Addr) bin_infos->allocd_segments[bin_infos->allocd_segs_len-1].segment_ptr;
        new_page_start = new_page_start + bin_infos->last_mapping_size;  // add to the previous addr the mapping size
        new_page_start = ALIGN_TO_PAGE_UP(new_page_start, bin_infos->elf_page_size);  // make it page aligned
        pa = mmap((void*)new_page_start, DEFAULT_STACK_SIZE, stack_flags,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (MAP_FAILED == pa) {
            PRINT_CUSTOM_ERROR("Failed to allocate memory at address %p with size %d", (void*)new_page_start, DEFAULT_STACK_SIZE);
            PRINT_ERROR("Error from mmap");
            goto ret;
        }
        if (pa != (void*)new_page_start) {
            JMP_W_CERROR("Failed to allocate memory for segment at correct address. \n"
                             "Provided addr by mmap: %p vs. calculated addr from hdr: %p", ret, pa, (void*)new_page_start)
        }
    }

    // append pointer to the mapped stack region to the binary information struct for later reference/cleanup
    bin_infos->initial_user_stack = pa;

    /* Create the initial user stack in the new memory mapping manually
     * Layout:
        ----- low memory -----
        <actual argv values>
        argc            <-- rsp
        argv[0]
        ...
        argv[argc-1]
        NULL            --> argv terminator
        NULL            --> envp terminator
        auxv            --> ...
        ----- high memory -----

    * Set the auxiliary vector (auxv) pairs according to the elf file and our environment and
    * the kernel/machine specific auxv pairs according to what the kernel did pass to this loader
    */
    {/* We need this block to have the variable-length-array out of scope for the goto's;
        Otherwise gcc gives us an error, cause apparently its illegal to have a goto jmp into the scope of a VLA */
        // define kind of a stack pointer (of type XWord cause it points to raw data), 7 MiB into stack memory
        Elf64_Xword* _sp = (Elf64_Xword*)((Elf64_Xword)pa+1024*1024*7);

        ALIGN_SP(_sp);  // make it aligned to 16
        bin_infos->initial_user_stack_sp = (void*)_sp;  // let the (loaded programs) stack pointer have this value
        PUSH(argc, _sp);  // Append argc to the stack as a 64-bit unsigned number
        Elf64_Addr* _sp_argv = _sp;  // we will populate argv later
        _sp = (Elf64_Addr*)((Elf64_Addr)_sp + POINTER_SIZE * argc);  // make room for the string pointers of argv
        PUSH(NULL, _sp);  // terminate argv
        PUSH(NULL, _sp);  // terminate envp

        // push all the needed auxiliary vectors
        Elf64_auxv_t* auxv = (Elf64_auxv_t*)_sp;  // define an array for auxv
        int auxv_index = 0;
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_PHDR, .a_un = {(bin_infos->phdr_table_vaddr)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_PHENT, .a_un = {bin_infos->elf_header->e_phentsize}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_PHNUM, .a_un = {bin_infos->elf_header->e_phnum}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_PAGESZ, .a_un = {bin_infos->elf_page_size}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_BASE, .a_un = {0x00}};  // we dont have an interpreter
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_FLAGS, .a_un = {getauxval(AT_FLAGS)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_ENTRY, .a_un = {bin_infos->entrypoint}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_UID, .a_un = {getuid()}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_EUID, .a_un = {geteuid()}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_GID, .a_un = {getgid()}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_EGID, .a_un = {getegid()}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_CLKTCK, .a_un = {sysconf(_SC_CLK_TCK)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_PLATFORM, .a_un = {getauxval(AT_PLATFORM)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_HWCAP, .a_un = {getauxval(AT_HWCAP)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_HWCAP2, .a_un = {getauxval(AT_HWCAP2)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_HWCAP3, .a_un = {getauxval(AT_HWCAP3)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_HWCAP4, .a_un = {getauxval(AT_HWCAP4)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_SECURE, .a_un = {getauxval(AT_SECURE)}};
        const int auxv_rand_bytes_i = auxv_index;  // save the index to AT_RANDOM to set it later
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = {(uint64_t)0x00}};  // we fill set this later
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_RSEQ_FEATURE_SIZE, .a_un = {getauxval(AT_RSEQ_FEATURE_SIZE)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_RSEQ_ALIGN, .a_un = {getauxval(AT_RSEQ_ALIGN)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_EXECFN, .a_un = {(uint64_t)_sp_argv}};  // ptr to argv[0]
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_SYSINFO_EHDR, .a_un = {getauxval(AT_SYSINFO_EHDR)}};
        auxv[auxv_index++] = (Elf64_auxv_t){.a_type = AT_MINSIGSTKSZ, .a_un = {getauxval(AT_MINSIGSTKSZ)}};
        auxv[auxv_index] = (Elf64_auxv_t){.a_type = AT_NULL, .a_un = {0}};  // end of auxiliary vector

        _sp = (Elf64_Addr*)((Elf64_Addr)_sp + sizeof(Elf64_auxv_t) * (auxv_index+1));  // move _sp to the end of auxv
        ALIGN_SP(_sp);  // make it aligned to 16

        // Build the argv string table
        ssize_t string_length = 0;
        for (int i = 0; i<argc; i++) {
            string_length = memcpy_n(_sp, argv[i]);  // copy the string from argv[i] to the stack
            PUSH(_sp, _sp_argv);  // populate argv with the addresses to the strings
            _sp = (Elf64_Xword *) ((Elf64_Xword)_sp + string_length);  // increment stack pointer
        }

        // push the random bytes for gcc's TLS seeding onto stack
        ALIGN_SP(_sp);
        Elf64_Addr* random_bytes = _sp;
        // create 16 random bytes - for now this is 'random' enough
        for (size_t i = 0; i < 16; i++) random_bytes[i] = (unsigned char)(rand() % 256);  // cast random int to char

        /* stack pointer invalid from here (if needed, _sp = _sp+16) */

        auxv[auxv_rand_bytes_i] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = {(uint64_t)random_bytes}};
    }

    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for freeing all the loader-internal memory, closing all files, etc...
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 */
void loader_cleanup(bin_info_table_T* bin_infos) {
    DEBUG("Cleaning up loader internal stuff")
    free(bin_infos->prog_header_table);
    bin_infos->prog_header_table = nullptr;
    free(bin_infos->elf_header);
    bin_infos->elf_header = nullptr;
    free(bin_infos->allocd_segments);
    bin_infos->allocd_segments = nullptr;
    close(bin_infos->elf_fd);  // if this fails, we just ignore it
    bin_infos->elf_fd = -1;
}

/**
 * Function for cleaning up the loaded process image in case of an error
 *
 * @param bin_infos Pointer to data field for storing and retrieving information
 */
void proc_img_cleanup(const bin_info_table_T* bin_infos) {
    DEBUG("Cleaning up new process image")
    if (nullptr == bin_infos->allocd_segments) goto allocd_segs_free_end;
    for (int i = 0; i<bin_infos->allocd_segs_len; i++) {
        if (MAP_FAILED != bin_infos->allocd_segments[i].segment_ptr)
            munmap(bin_infos->allocd_segments[i].segment_ptr, bin_infos->allocd_segments[i].segment_size);
    }
    allocd_segs_free_end:
    if (MAP_FAILED != bin_infos->initial_user_stack) munmap(bin_infos->initial_user_stack, sizeof(void*));
}

/**
 * Main function to start the loading and executing of the ELF binary
 *
 * @param argc The length of argv
 * @param argv [1] The path and file name to the ELF binary
 * @param argv [2:] The argv to pass to the new process
 */
int main(const int argc, char **argv) {
    DEBUG("Entering main");
    if (argc < 2) {
        printf("Usage: %s <path/to/ELF/binary>\n", *argv);
        return 0;
    }
    srand(time(nullptr));

    bin_info_table_T binary_infos = {0};  // initialize everything to zero
    binary_infos.sys_page_size = getpagesize();

    if (0 > open_and_parse_elf(&binary_infos, argv[1])) JMP_W_CERROR("Failed to load ELF header", on_error);

    if (0 > load_alloc_segments(&binary_infos)) JMP_W_CERROR("Failed to load segments", on_error);

    if (0 > create_initial_stack(&binary_infos, argc-1, argv+1)) JMP_W_CERROR("Failed to create initial stack", on_error);

    loader_cleanup(&binary_infos);

    printf("\n******************************************\n"
           "* Transferring control to loaded program *\n"
           "******************************************\n\n");
    fflush(nullptr);

    transfer_control((void*)binary_infos.entrypoint, binary_infos.initial_user_stack_sp);

    /* if we came here, something went wrong
     * --> clean everything up and exit the program  */
    on_error:
    proc_img_cleanup(&binary_infos);
    loader_cleanup(&binary_infos);
    return -EXIT_FAILURE;
}