// ToDo: Replace all fread-error prints with proper error handling (feof and ferror)

// Includes
#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include "common.h"
// assembly functions
extern void transfer_control(void* entry_point, void* stack_addr);
ssize_t memcpy_n(void* dest, const void* src);

// Macros
#define ELF_HEADER_SIZE (sizeof(Elf64_Ehdr))
#define NOP __asm__("NOP")  // No-Operation - assembly instruction
#define GET_PHDR_ENTRY(_e_phoff, _e_phentsize) (_e_phoff + i * _e_phentsize)

// I know those macro are of bad coding style, but it also helps massively in reducing duplicate code, so I take it
#define JMP_W_CERROR(ERROR_STR, JMP_LABEL, ...) { PRINT_CUSTOM_ERROR(ERROR_STR __VA_OPT__(,) __VA_ARGS__); goto JMP_LABEL; }
#define JMP_W_ERROR(ERROR_STR, JMP_LABEL) { PRINT_ERROR(ERROR_STR); goto JMP_LABEL; }


typedef struct bin_info_table_S {
    Elf64_Addr  entrypoint;  // this maybe zero
    FILE* elf_fstream;
    Elf64_Ehdr* elf_header;
    Elf64_Phdr* prog_header_table;
    int allocd_segs_size;  // len of allocd_segs array
    Elf64_Addr* allocd_segs_sizes;  // len of each allocd_segs mapping
    void* initial_user_stack;
    void** allocd_segs;  // array of pointer to allocated segments
} bin_info_table_T;

/**
 * Function for seeking with offsets of greater length than `long', namely up to an offsets of type `Elf64_Off'
 * @param fp file stream pointer to seek in
 * @param offset offset to seek within the file
 */
// void safe_fseek(FILE *fp, const Elf64_Off offset) {
//     if (offset > LONG_MAX) {
//         fseek(fp, LONG_MAX, SEEK_SET);
//         fseek(fp, (long)(offset - LONG_MAX), SEEK_CUR);
//     } else {
//         fseek(fp, (long)offset, SEEK_SET);
//     }
// }

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
    int retval = -ENOEXEC;
    errno = retval;

    // create a stdio file obj to the elf binary
    FILE* elf_file_stream = fopen(filename, "r");
    if (NULL == elf_file_stream) JMP_W_ERROR("Failed to open the ELF binary", ret);
    bin_infos->elf_fstream = elf_file_stream;
    fseek(elf_file_stream, 0L, SEEK_END);
    const Elf64_Off file_size = ftell(elf_file_stream);  // implicitly cast this to an Elf64_Off type
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

    // next get the entrypoint (as a virtual address) of the program for it to start
    bin_infos->entrypoint = elf_header->e_entry;  // this maybe zero

    // check if the header exits
    if (!elf_header->e_phoff) JMP_W_CERROR("Program header table size if 0", ret);
    //check if the header offset does point to a valid location within the file
    if (elf_header->e_phoff > file_size) JMP_W_CERROR("Program header table is beyond EOF", ret);

    /* we can ignore the section header (I think/hope) as this program is purly
     * intended for loading ELF files, not for linking or relocating stuff */

    // next get the program header table
    /* for now, we just ignore the fact that if the file size is greater than a long,
     * and simply 'throw' a raw error when the seek fails */
    if (0 > fseeko(elf_file_stream, elf_header->e_phoff, SEEK_SET))
        JMP_W_ERROR("Failed to seek in file - possibly because its too large for fseeko to handle", ret);
    const Elf64_Word phdrtsize = elf_header->e_phentsize * elf_header->e_phnum;
    Elf64_Phdr* phdrtable = calloc(1, phdrtsize);  // program header table
    if (NULL == phdrtable) JMP_W_ERROR("Failed to allocate space for the pogram-header-buffer", ret);

    bin_infos->prog_header_table = phdrtable;
    if (phdrtsize != fread(phdrtable, 1, phdrtsize, elf_file_stream))
        JMP_W_CERROR("Failed to read the program header table", ret);

    return 0;  // we assume if we came here everything is good :)
    ret:
    if (-errno != retval) return -errno;  // return errno if it's not the same as retval
    return retval;  // else we return the retval code
}

int load_alloc_segments(bin_info_table_T* bin_infos, int argc, char** argv) {
    int retval = -EIO;  // we just make an I/O-Error the default here
    void*** allocd_segs = &bin_infos->allocd_segs;  // pointer to address of array allocd_segs
    Elf64_Addr** allocd_segs_sizes = &bin_infos->allocd_segs_sizes;  // pointer to address of array allocd_segs_size
    Elf64_Xword page_size = 0;      // page size specified in the elf program headers - for later usage
    Elf64_Addr mapping_size = 0;    // define the variable that will hold the mapping size here for later usage

    // iterate over the program header table and load the segments we need --> p_type=PT_LOAD
    for (Elf64_Half i = 0; i<bin_infos->elf_header->e_phnum; i++) {
        Elf64_Phdr phdr_entry = bin_infos->prog_header_table[i];  // get the next program header entry
        if (PT_LOAD != phdr_entry.p_type && PT_TLS != phdr_entry.p_type) continue;
        if (!page_size) page_size = phdr_entry.p_align;

        // if we found a loadable segment, allocate memory for the pointer to store it into the array
        bin_infos->allocd_segs_size++;  // increase the length index
        // (re)alloc the segment-mapping-address array
        void* new_ptr = realloc(*allocd_segs, sizeof(void*)*bin_infos->allocd_segs_size);
        if (NULL == new_ptr) JMP_W_CERROR("Realloc failed on segment-mapping-address array", ret);
        *allocd_segs = new_ptr;  // assign the new space to the array
        // also (re)alloc the segment-mapping-sizes array
        new_ptr = realloc(*allocd_segs_sizes, sizeof(void*)*bin_infos->allocd_segs_size);
        if (NULL == new_ptr) JMP_W_CERROR("Realloc failed segment-mapping-sizes array", ret);
        *allocd_segs_sizes = new_ptr;  // assign the new space to the array

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

        Elf64_Addr page_start = phdr_entry.p_vaddr - phdr_entry.p_vaddr % phdr_entry.p_align;
        Elf64_Addr page_offset = phdr_entry.p_vaddr - page_start;
        mapping_size = page_offset + phdr_entry.p_memsz;
        bin_infos->allocd_segs_sizes[i] = mapping_size;
        // always set the protection of the mapping to write, cause we still have to write the segment data
        void* const pa = mmap((void*)page_start, mapping_size, PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (MAP_FAILED == pa) {
            PRINT_CUSTOM_ERROR("Failed to allocate memory at address %p with size %lu", (void*)page_start, mapping_size);
            PRINT_ERROR("Error from mmap");
            goto ret;
        }
        *(*allocd_segs+bin_infos->allocd_segs_size-1) = pa;  // store pointer for later usage...
        if (pa != (void*)page_start)
            JMP_W_CERROR("Failed to allocate memory for segment at correct address. \n"
                         "Provided addr by mmap: %p vs. calculated addr from hdr: %p", ret, pa, (void*)page_start)

        DEBUG("Successfully created memory mapping at address %p with size %lu", (void*)page_start, mapping_size);
        fflush(stdout);

        // read in the segment data from the elf file and write it into the allocated memory of the segment
        // also here, we ignore the fact that p_offset could be too large for fseek
        if (0 > fseeko(bin_infos->elf_fstream, phdr_entry.p_offset, SEEK_SET))
            JMP_W_ERROR("Failed to seek in file - possibly because its too large for fseeko to handle", ret);
        if (phdr_entry.p_filesz != fread((void*)(page_start+page_offset), 1, phdr_entry.p_filesz, bin_infos->elf_fstream))
            JMP_W_CERROR("Failed to read segment from file", ret);
        // memset doesn't return an error, so we assume that this is always successful - idk :)
        memset(pa, 0x00, phdr_entry.p_memsz - phdr_entry.p_filesz);

        // next set the actual (correct) flags for this memory mapping
        const int mmap_seg_prot = (phdrflags & PF_X ? PROT_EXEC : 0) | (phdrflags & PF_W ? PROT_WRITE : 0) | (phdrflags & PF_R ? PROT_READ : 0);
        if (-1 == mprotect(pa, phdr_entry.p_memsz, mmap_seg_prot)) JMP_W_ERROR("memprotect failed", ret);
    }

    /* finally create a new memory mapping for argc, argv, etc.
     * For that we calculate the beginning of the next page starting from the last memory mapping
     * By doing that here, we have some code duplication but this is inevitable
     * We assume that the program header entry variable (phdr_entry) is already initialized
     * We also assume that the address of the last mapped section is already page aligned (- it has to be)
     */
    Elf64_Addr new_page_start = (Elf64_Addr) bin_infos->allocd_segs[bin_infos->allocd_segs_size-1];
    new_page_start = new_page_start + mapping_size;  // add to the previous addr the mapping size
    new_page_start = new_page_start + (page_size - new_page_start % page_size);  // make it page aligned

    size_t argv_size = sizeof(char*) * argc;  // begin by adding the space needed for the pointers
    for (int i = 0; i<argc; i++) argv_size += strlen(argv[i]);  // calculate and add the size of each string

    const size_t new_mapping_size = sizeof(int) + argv_size + sizeof(unsigned char);  // sizeof (argc, argv, NULL)
    void* const pa = mmap((void*)new_page_start, new_mapping_size, PROT_WRITE | PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (MAP_FAILED == pa) {
        PRINT_CUSTOM_ERROR("Failed to allocate memory at address %p with size %lu", (void*)new_page_start, new_mapping_size);
        PRINT_ERROR("Error from mmap");
        goto ret;
    }
    if (pa != (void*)new_page_start) {
        JMP_W_CERROR("Failed to allocate memory for segment at correct address. \n"
                         "Provided addr by mmap: %p vs. calculated addr from hdr: %p", ret, pa, (void*)new_page_start)
    }

    // Create the initial user stack in the new memory mapping manually
    /* Layout:
        argc
        argv[0]
        ...
        argv[argc-1]
        NULL              --> argv terminator
        NULL              --> envp terminator
        auxv              --> AT_NULL | 0x00
     */
    *(Elf64_Xword*)pa = argc;  // First append argc to the stack as a 64-bit unsigned number
    // *(int*)pa = 0;  // Add some padding between argc and argv so its 8 bytes instead of 4 bytes

    // Next build the argv string table
    const int omitted_elements = 4;  // namely the NULL after argv, envp and the auxv pair
    ssize_t string_length = 0;
    Elf64_Addr _sp = (Elf64_Addr)pa+sizeof(Elf64_Xword*);  // define kind of a stack pointer
    for (int i = 0; i<argc; i++) {
        // Todo: This string address calculation is completely wrong - have to take into account `i` and the string length
        const Elf64_Addr string_address = _sp + (argc - i + omitted_elements) * sizeof(char*) + string_length;
        string_length += memcpy_n((char*)string_address, argv[i]);  // copy the string from argv[i] to the stack
        *(char**)_sp = (char*)string_address;  // 'push' the addr to the copied string onto stack
        _sp += sizeof(char*);
    }
    *((char**)_sp+0) = nullptr;  // 'push' null terminator onto stack to terminate argv
    *((char**)_sp+1) = nullptr;  // 'push' null terminator onto stack to have an empty envp
    *((char**)_sp+2) = AT_NULL;  // 'push' AT_NULL onto stack for empty auxv pair
    *((char**)_sp+3) = nullptr;  // 'push' null onto stack for empty auxv pairs
    bin_infos->initial_user_stack = pa;  // append it to the binary information struct for later reference/cleanup

    return 0;
    ret:
    if (-errno != retval) return -errno;  // return errno if it's not the same as retval
    return retval;  // else we return the retval code
}

void cleanup(bin_info_table_T* bin_info) {
    DEBUG("Cleaning up")
    free(bin_info->prog_header_table);
    bin_info->prog_header_table = nullptr;
    free(bin_info->elf_header);
    bin_info->elf_header = nullptr;
    if (nullptr == bin_info->allocd_segs) goto allocd_segs_free_end;
    for (int i = 0; i<bin_info->allocd_segs_size; i++) {
        if (MAP_FAILED != bin_info->allocd_segs[i]) munmap(bin_info->allocd_segs[i], bin_info->allocd_segs_sizes[i]);
    }
    free(bin_info->allocd_segs);
    allocd_segs_free_end:
    free(bin_info->allocd_segs_sizes);
    if (MAP_FAILED != bin_info->initial_user_stack) munmap(bin_info->initial_user_stack, sizeof(void*));
}

/**
 * Main function to start the loading and executing of the ELF binary
 *
 * @param argc
 * @param argv [1] The path and file name to the ELF binary
 */
int main(const int argc, char **argv) {
    DEBUG("Entering main");
    if (argc < 2) {
        printf("Usage: %s <path/to/ELF/binary>", *argv);
        return 0;
    }
    int retval = EXIT_SUCCESS;

    bin_info_table_T binary_infos = {
        .entrypoint = 0x000000000000,  // empty 64-bit address
        .elf_header = nullptr,
        .prog_header_table = nullptr,
        .allocd_segs_size = 0,
        .allocd_segs = nullptr,
        .elf_fstream = nullptr,
        .initial_user_stack = nullptr,
    };

    if (0 > open_and_parse_elf(&binary_infos, argv[1])) JMP_W_CERROR("Failed to load ELF header", on_error);

    if (0 > load_alloc_segments(&binary_infos, argc-1, argv+1)) JMP_W_CERROR("Failed to load segments", on_error);

    fflush(nullptr);
    transfer_control((void*)binary_infos.entrypoint, binary_infos.initial_user_stack);

    do_cleanup:
    cleanup(&binary_infos);
    return retval;
    on_error:
    retval = -EXIT_FAILURE;
    goto do_cleanup;
}