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

#include "main.h"

typedef struct bin_info_table_S {
    Elf64_Addr  entrypoint;         // this maybe zero
    FILE*       elf_fstream;        // file stream of the ELF file
    __u_long    elf_file_size;      // size of the complete efi file
    Elf64_Ehdr* elf_header;         // pointer to allocated memory storing the elf header
    Elf64_Phdr* prog_header_table;  // pointer to allocated memory storing the program header table
    Elf64_Shdr* sect_header_table;  // pointer to allocated memory storing the section header table
    int         allocd_segs_len;    // len of allocd_segs array
    Elf64_Addr* allocd_segs_sizes;  // len of each allocd_segs mapping
    void*       initial_user_stack; // points to the beginning (lowest address) of the stack
    void*       initial_user_stack_sp;  // stack pointer to set for the initial user stack
    void**      allocd_segs;        // array of pointer to allocated segments
    Elf64_Addr  last_mapping_size;  // holds the last mapping size --> for calculating the next mapping
    Elf64_Xword page_size;          // page size specified in the elf program headers
    Elf64_Phdr* phdr_table_vaddr;   // virtual address of the process header loaded into memory relative to the first loaded segment
} bin_info_table_T;

/**
 * Function for seeking with offsets of greater length than `long', namely up to an offsets of type `Elf64_Off'
 * @param stream File stream to seek in
 * @param offset Offset to seek within the file
 * @param whence Position to begin seeking in the file
 */
int safe_fseeko(FILE *stream, Elf64_Off offset, int whence) {
    STANDARD_FUNCTION_START

    // First have this fseeko block so we can use the whence as a starting point
    if (offset > LONG_MAX) {
        if (0 > fseeko(stream, LONG_MAX, whence)) JMP_W_ERROR("Initial fseeko failed", ret);
        offset -= LONG_MAX;
        whence = SEEK_CUR;
    }

    // Next, while the offset is still greater than LONG_MAX, seek with LONG_MAX until its less or equal than LONG_MAX
    while (offset > LONG_MAX) {
        if (0 > fseeko(stream, LONG_MAX, whence)) JMP_W_ERROR("Iterative fseeko failed", ret);
        offset -= LONG_MAX;
    }

    // Finally, the offset the less or equal to LONG_MAX so we seek with the offset that is left (cast to a long)
    if (0 > fseeko(stream, (long)offset, whence)) JMP_W_ERROR("Closing fseeko failed", ret);

    // Just return -errno in any case as we don't have any other instructions that would need a retval themselves
    STANDARD_FUNCTION_RETURN(-errno);
}

/**
 * Function for extracting the program- and section- header table from the elf file given the offset, its size and the amount of entries
 *
 * @param bin_infos Pointer to data field for storing the return values of this function
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

    const char* hdr_t_type = bin_infos->elf_header->e_phoff == offset ? "program" : "section";

    // check if the header table exits
    if (!offset) JMP_W_CERROR("%s header table size if 0", ret, hdr_t_type);
    // check if the header table offset does point to a valid location within the file
    if (offset > bin_infos->elf_file_size) JMP_W_CERROR("%s header table is beyond EOF", ret, hdr_t_type);

    // next get the header table
    /* for now, we just ignore the fact that if the file size is greater than a long,
     * and simply 'throw' a raw error when the seek fails */
    if (0 > fseeko(bin_infos->elf_fstream, offset, SEEK_SET))
        JMP_W_ERROR("Failed to seek in file - possibly because its too large for fseeko to handle", ret);
    const Elf64_Word phdrtsize = hdr_t_size * hdr_t_ent;
    void* hdr_buffer = calloc(1, phdrtsize);  // header table size
    if (NULL == hdr_buffer) {
        PRINT_CUSTOM_ERROR("Failed to allocate space for the %s-header-table-buffer", hdr_t_type);
        JMP_W_ERROR("Detailed allocation error", ret);
    }
    // read the header from the elf file and check, if we got all the bytes
    if (phdrtsize != fread(hdr_buffer, 1, phdrtsize, bin_infos->elf_fstream))
        JMP_W_CERROR("Failed to read the %s header table", ret, hdr_t_type);

    *hdr_t_ptr = hdr_buffer;
    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for opening and gathering information from the ELF binary, like checking its properties or
 * extracting header- and general information
 * Basically, every field is processed in the same order as they appear in the man-page --> `man elf`
 *
 * @param bin_infos Pointer to data field for storing the return values of this function
 * @param filename Path to and Filename of the ELF binary
 * @return Returns 0 if successful, an errno code if not successful
 */
int open_and_parse_elf(bin_info_table_T* bin_infos, const char* filename) {
    DEBUG("Parsing elf file");
    STANDARD_FUNCTION_START;

    // create a stdio file obj to the elf binary
    FILE* elf_file_stream = fopen(filename, "r");
    if (NULL == elf_file_stream) JMP_W_ERROR("Failed to open the ELF binary", ret);
    bin_infos->elf_fstream = elf_file_stream;
    fseek(elf_file_stream, 0L, SEEK_END);
    bin_infos->elf_file_size = ftell(elf_file_stream);
    rewind(elf_file_stream);

    // get the elf file header
    Elf64_Ehdr* elf_header = calloc(1, ELF_HEADER_SIZE);
    if (NULL == elf_header) JMP_W_CERROR("Failed to allocate space for the efi-header-buffer", ret);
    bin_infos->elf_header = elf_header;
    if (ELF_HEADER_SIZE != fread(elf_header, 1, ELF_HEADER_SIZE, elf_file_stream))
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
    if (ET_EXEC != elf_header->e_type) JMP_W_CERROR("EFI file is not an executable", ret);
    // check if the elf file contains the correct target instruction set architecture (64-bit / for instructions)
    if (EM_X86_64 != elf_header->e_machine) JMP_W_CERROR("EFI file has the wrong instruction set architecture", ret);

    // next get the entrypoint (as a virtual address) of the program
    bin_infos->entrypoint = elf_header->e_entry;  // this maybe zero

    // next get the program header table if it exists
    if (0 > get_header_table(bin_infos, elf_header->e_phoff, elf_header->e_phentsize,
                        elf_header->e_phnum, (void*)&bin_infos->prog_header_table)) {
        JMP_W_CERROR("Failed to load program header table", ret)
    }

    // get the section header table if it exists
    if (0 > get_header_table(bin_infos, elf_header->e_shoff, elf_header->e_shentsize,
                             elf_header->e_shnum, (void*)&bin_infos->sect_header_table)) {
        JMP_W_CERROR("Failed to load section header table", ret)
    }

    STANDARD_FUNCTION_RETURN(-ENOEXEC);
}

/**
 * Function for allocating or resizing an array by @param type_s * @param array_size
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
 * Function for loading the segment headers from the program header table into memory
 * and mapping all the relevant segments into the virtual address space of the new process
 *
 * @param bin_infos Pointer to data field for storing the return values of this function
 * @return Returns 0 if successful, an errno code if not successful
 */
int load_alloc_segments(bin_info_table_T* bin_infos) {
    STANDARD_FUNCTION_START;

    // iterate over the program header table and load the segments we need --> p_type=PT_LOAD
    for (Elf64_Half i = 0; i<bin_infos->elf_header->e_phnum; i++) {
        const Elf64_Phdr phdr_entry = bin_infos->prog_header_table[i];  // get the next program header entry
        if (PT_LOAD != phdr_entry.p_type && PT_TLS != phdr_entry.p_type) continue;  // skip all other segments
        if (!bin_infos->page_size && 0 != phdr_entry.p_align) bin_infos->page_size = phdr_entry.p_align;
        if (!bin_infos->phdr_table_vaddr) bin_infos->phdr_table_vaddr = (Elf64_Phdr*)(phdr_entry.p_vaddr + bin_infos->elf_header->e_phoff);

        // if we found a loadable segment, allocate memory for the pointer to store it into the array
        bin_infos->allocd_segs_len++;  // increase the length index
        if (0 > realloc_array((void**)&bin_infos->allocd_segs, &bin_infos->allocd_segs_len, POINTER_SIZE))
            JMP_W_CERROR("Realloc failed on segment-mapping-address array", ret)

        // also (re)alloc the segment-mapping-sizes array
        if (0 > realloc_array((void**)&bin_infos->allocd_segs_sizes, &bin_infos->allocd_segs_len, sizeof(Elf64_Addr)))
            JMP_W_CERROR("Realloc failed on segment-mapping-sizes array", ret)

        // next allocate the actual segment with the correct address
        const Elf64_Word phdrflags = phdr_entry.p_flags;

        // TODO: replace fd with efi file descriptor and load the segment directly from the efi file

        /* TODO FINISHED: Calculate the correct page start and map from the offset
         * page_start = vaddr - (vaddr - align)
         * so now page_start % align = 0
         *
         * Calculate the size of the mapping:
         * page_offset = p_vaddr - page_start
         * mapping_size = page_offset + p_memsz
         *
         * Write data into page mapping at:
         * page_start + page_offset
         */

        const Elf64_Addr page_start = phdr_entry.p_vaddr - phdr_entry.p_vaddr % bin_infos->page_size;
        const Elf64_Addr page_offset = phdr_entry.p_vaddr - page_start;
        const Elf64_Addr mapping_size = page_offset + phdr_entry.p_memsz;
        bin_infos->last_mapping_size = mapping_size;
        bin_infos->allocd_segs_sizes[i] = mapping_size;
        // always set the protection of the mapping to write, cause we still have to write the segment data
        void* const pa = mmap((void*)page_start, mapping_size, PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (MAP_FAILED == pa) {
            PRINT_CUSTOM_ERROR("Failed to allocate memory at address %p with size %lu", (void*)page_start, mapping_size);
            PRINT_ERROR("Error from mmap");
            goto ret;
        }
        bin_infos->allocd_segs[bin_infos->allocd_segs_len-1] = pa;
        if (pa != (void*)page_start)
            JMP_W_CERROR("Failed to allocate memory for segment at correct address. \n"
                         "Provided addr by mmap: %p vs. calculated addr from hdr: %p", ret, pa, (void*)page_start)

        DEBUG("Successfully created memory mapping at address %p with size %lu of type %s", (void*)page_start,
            mapping_size, phdr_entry.p_type == PT_LOAD ? M_TO_STR(PT_LOAD) : M_TO_STR(PT_TLS));
        fflush(stdout);

        // read in the segment data from the elf file and write it into the allocated memory of the segment
        // also here, we ignore the fact that p_offset could be too large for fseek
        if (0 > fseeko(bin_infos->elf_fstream, phdr_entry.p_offset, SEEK_SET))
            JMP_W_ERROR("Failed to seek in file - possibly because its too large for fseeko to handle", ret);
        if (phdr_entry.p_filesz != fread((void*)(page_start+page_offset), 1, phdr_entry.p_filesz, bin_infos->elf_fstream))
            JMP_W_CERROR("Failed to read segment from file", ret);
        // memset doesn't return an error, so we assume that this is always successful - idk :)
        memset((void*)((Elf64_Addr)pa+phdr_entry.p_filesz), 0x00, phdr_entry.p_memsz - phdr_entry.p_filesz);

        // next set the actual (correct) flags for this memory mapping
        const int mmap_seg_prot = (phdrflags & PF_X ? PROT_EXEC : 0) | (phdrflags & PF_W ? PROT_WRITE : 0) | (phdrflags & PF_R ? PROT_READ : 0);
        if (-1 == mprotect(pa, phdr_entry.p_memsz, mmap_seg_prot)) JMP_W_ERROR("memprotect failed", ret);
    }

    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for creating the initial user stack and filling it with argc, argv, envp and auxv
 *
 * @param bin_infos Pointer to data field for storing the return values of this function
 * @param argc The length of argv
 * @param argv The argv to pass to the new process
 * @return Returns 0 if successful, an errno code if not successful
 */
int create_initial_stack(bin_info_table_T* bin_infos, const int argc, char** argv) {
    STANDARD_FUNCTION_START;

    /* Create a new memory mapping for argc, argv, etc.
     * For that we calculate the beginning of the next page starting from the last memory mapping
     * By doing that here, we have some code duplication but this is inevitable
     * We assume that the program header entry variable (phdr_entry) is already initialized
     * We also assume that the address of the last mapped section is already page aligned (- it has to be)
     */
    Elf64_Addr new_page_start = (Elf64_Addr) bin_infos->allocd_segs[bin_infos->allocd_segs_len-1];
    new_page_start = new_page_start + bin_infos->last_mapping_size;  // add to the previous addr the mapping size
    new_page_start = new_page_start + (bin_infos->page_size - new_page_start % bin_infos->page_size);  // make it page aligned
    void* const pa = mmap((void*)new_page_start, DEFAULT_STACK_SIZE, PROT_WRITE | PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (MAP_FAILED == pa) {
        PRINT_CUSTOM_ERROR("Failed to allocate memory at address %p with size %d", (void*)new_page_start, DEFAULT_STACK_SIZE);
        PRINT_ERROR("Error from mmap");
        goto ret;
    }
    if (pa != (void*)new_page_start) {
        JMP_W_CERROR("Failed to allocate memory for segment at correct address. \n"
                         "Provided addr by mmap: %p vs. calculated addr from hdr: %p", ret, pa, (void*)new_page_start)
    }

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

        Elf64_Addr* random_bytes = _sp;
        // create 16 random bytes - for now this is 'random' enough
        PUSH("1", _sp);  // 8 bytes
        PUSH("2", _sp);  // 8 bytes

        // First build the argv string table so that the size of the strings don't matter when building the rest of the stack
        Elf64_Addr* string_table_ptrs[argc-1];
        // const int omitted_elements = 4;  // namely the NULL after argv, envp and the auxv pair
        ssize_t string_length = 0;
        for (int i = 0; i<argc; i++) {
            // Elf64_Addr* string_address = (Elf64_Addr*)((Elf64_Xword)_sp + (argc - i + omitted_elements) * POINTER_SIZE + string_length);
            string_length = memcpy_n(_sp, argv[i]);  // copy the string from argv[i] to the stack
            //PUSH(string_address, _sp);  // 'push' the addr to the copied string onto stack
            string_table_ptrs[i] = _sp;
            _sp = (Elf64_Xword *) ((Elf64_Xword)_sp + string_length);  // increment stack pointer
        }
        _sp = (Elf64_Xword*)((Elf64_Xword)_sp + 16 - (Elf64_Xword)_sp % 16);  // make it aligned to 16
        bin_infos->initial_user_stack_sp = (void*)_sp;  // let the (loaded programs) stack pointer have this value
        PUSH(argc, _sp);  // Append argc to the stack as a 64-bit unsigned number
        for (int i = 0; i<argc; i++) PUSH(string_table_ptrs[i], _sp);  // populate argv with the addresses to the strings
        PUSH(NULL, _sp);  // terminate argv
        PUSH(NULL, _sp);  // terminate envp

        // push all the needed auxiliary vectors
        Elf64_auxv_t* auxv = (Elf64_auxv_t*)_sp;  // define an array for auxv
        int i = 0;
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_PHDR, .a_un = {(uint64_t)bin_infos->phdr_table_vaddr}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_PHENT, .a_un = {bin_infos->elf_header->e_phentsize}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_PHNUM, .a_un = {bin_infos->elf_header->e_phnum}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_PAGESZ, .a_un = {bin_infos->page_size}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_BASE, .a_un = {0x00}};  // we dont have an interpreter
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_FLAGS, .a_un = {0x00}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_ENTRY, .a_un = {bin_infos->elf_header->e_entry}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_UID, .a_un = {getuid()}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_EUID, .a_un = {geteuid()}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_GID, .a_un = {getgid()}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_EGID, .a_un = {getegid()}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_CLKTCK, .a_un = {sysconf(_SC_CLK_TCK)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_PLATFORM, .a_un = {getauxval(AT_PLATFORM)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_HWCAP, .a_un = {getauxval(AT_HWCAP)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_HWCAP2, .a_un = {getauxval(AT_HWCAP2)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_HWCAP3, .a_un = {getauxval(AT_HWCAP3)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_HWCAP4, .a_un = {getauxval(AT_HWCAP4)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_SECURE, .a_un = {0}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_RANDOM, .a_un = {(uint64_t)random_bytes}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_RSEQ_FEATURE_SIZE, .a_un = {getauxval(AT_RSEQ_FEATURE_SIZE)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_RSEQ_ALIGN, .a_un = {getauxval(AT_RSEQ_ALIGN)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_EXECFN, .a_un = {(uint64_t)string_table_ptrs[0]}};  // ptr to argv[0]
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_SYSINFO_EHDR, .a_un = {getauxval(AT_SYSINFO_EHDR)}};
        auxv[i++] = (Elf64_auxv_t){.a_type = AT_MINSIGSTKSZ, .a_un = {getauxval(AT_MINSIGSTKSZ)}};
        auxv[i] = (Elf64_auxv_t){.a_type = AT_NULL, .a_un = {0x00}};  // end of auxiliary vector

        bin_infos->initial_user_stack = pa;  // append it to the binary information struct for later reference/cleanup
    }

    STANDARD_FUNCTION_RETURN(-EIO);
}


/***/
int do_relocations(bin_info_table_T* bin_infos) {
    STANDARD_FUNCTION_START;

    // iterate over the section header table and parse them (shdr_entry.sh_type == SHT_RELA)
    for (Elf64_Half i = 0; i<bin_infos->elf_header->e_shnum; i++) {
        const Elf64_Shdr shdr_entry = bin_infos->sect_header_table[i];  // get the next section header entry
        if (SHT_RELA != shdr_entry.sh_type) continue;  // skip all other sections

        Elf64_Rela* rel_t_a = (Elf64_Rela*)shdr_entry.sh_addr;  // get one relocation table entry with attend
        for (Elf64_Half j = 0; j<shdr_entry.sh_size / shdr_entry.sh_entsize; j++) {
            const Elf64_Rela* reloc_entry = rel_t_a+j;
            if (R_X86_64_IRELATIVE == ELF64_R_TYPE(reloc_entry->r_info))
            *(void**)reloc_entry->r_offset = ((void* (*) (void)) reloc_entry->r_addend)();
            DEBUG("Did relocation to %p", *(void**)reloc_entry->r_offset)
        }
    }
    if (0) goto ret;
    STANDARD_FUNCTION_RETURN(-EIO);
}

/**
 * Function for freeing all the allocated memory, closing all files, etc...
 *
 * @param bin_infos Pointer to data field for storing the return values of this function
 * @return -
 */
void cleanup(bin_info_table_T* bin_infos) {
    DEBUG("Cleaning up")
    free(bin_infos->prog_header_table);
    bin_infos->prog_header_table = nullptr;
    free(bin_infos->elf_header);
    bin_infos->elf_header = nullptr;
    if (nullptr == bin_infos->allocd_segs) goto allocd_segs_free_end;
    for (int i = 0; i<bin_infos->allocd_segs_len; i++) {
        if (MAP_FAILED != bin_infos->allocd_segs[i]) munmap(bin_infos->allocd_segs[i], bin_infos->allocd_segs_sizes[i]);
    }
    free(bin_infos->allocd_segs);
    allocd_segs_free_end:
    free(bin_infos->allocd_segs_sizes);
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
    int retval = EXIT_SUCCESS;
    srand(time(NULL));

    bin_info_table_T binary_infos = {0};

    if (0 > open_and_parse_elf(&binary_infos, argv[1])) JMP_W_CERROR("Failed to load ELF header", on_error);

    if (0 > load_alloc_segments(&binary_infos)) JMP_W_CERROR("Failed to load segments", on_error);

    if (0 > create_initial_stack(&binary_infos, argc-1, argv+1)) JMP_W_CERROR("Failed to create initial stack", on_error);

    // if (0 > do_relocations(&binary_infos)) JMP_W_CERROR("Failed to do relocations", on_error);

    fflush(nullptr);
    transfer_control((void*)binary_infos.entrypoint, binary_infos.initial_user_stack_sp);

    do_cleanup:
    cleanup(&binary_infos);
    return retval;
    on_error:
    retval = -EXIT_FAILURE;
    goto do_cleanup;
}