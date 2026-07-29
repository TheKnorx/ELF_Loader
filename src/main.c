// Includes
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <string.h>

#include "common.h"

// Macros
#define ELF_HEADER_SIZE (sizeof(Elf64_Ehdr))
#define NOP __asm__("NOP")  // No-Operation - assembly instruction
#define GET_PHDR_ENTRY(_e_phoff, _e_phentsize) (_e_phoff + i * _e_phentsize)
// I know this macro is bad coding style, but it also helps massively in reducing duplicate code, so I take it
#define JMP_W_CERROR(ERROR_STR, JMP_LABEL) {PRINT_CUSTOM_ERROR("Architecture is not 64-bit"); goto JMP_LABEL;}

typedef struct bin_info_table_S {
    Elf64_Addr* entrypoint;  // this maybe zero
    Elf64_Ehdr* elf_header;
    Elf64_Phdr* prog_header_table;
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
    if (NULL == elf_file_stream) THROW_ERROR("Failed to open the ELF binary");
    fseek(elf_file_stream, 0L, SEEK_END);
    const Elf64_Off file_size = ftell(elf_file_stream);  // implicitly cast this to an Elf64_Off type
    rewind(elf_file_stream);

    // get the elf file header
    Elf64_Ehdr* elf_header = calloc(1, ELF_HEADER_SIZE);
    if (NULL == elf_header) {
        PRINT_CUSTOM_ERROR("Failed to allocate space for the header-buffer");
        goto ret;
    }
    bin_infos->elf_header = elf_header;
    if (ELF_HEADER_SIZE != fread(elf_header, 1, ELF_HEADER_SIZE, elf_file_stream)) {
        PRINT_CUSTOM_ERROR("Failed to read the elf header");
        goto ret;
    }

    /* Do consistency-checks to make sure it's an actual ELF file and also if we can process it */
    /* First do the checks on the e_ident field */
    // check the ELF magic number
    if (0 != memcmp(ELFMAG, elf_header->e_ident, SELFMAG)) JMP_W_CERROR("File is not an ELF file", ret);
    //check if the elf binary has the correct data architecture class (64-bit / for addresses, offsets, types, ...)
    if (ELFCLASS64 != elf_header->e_ident[4]) JMP_W_CERROR("Data architecture class is not 64-bit", ret);
    // check if the elf file is encoded in little endian
    if (ELFDATA2LSB != elf_header->e_ident[5]) JMP_W_CERROR("ELF file is not encoded in little-endian", ret);
    // check if the elf file has the correct version
    if (EI_VERSION != elf_header->e_ident[6] || EV_CURRENT != elf_header->e_version)
        JMP_W_CERROR("ELF File does not have the correct version", ret);
    // for now, we skip checking the EI_OSABI field

    // check if the elf file is indeed an executable file --> this is currently the only supported option
    if (ET_EXEC != elf_header->e_type) JMP_W_CERROR("EFI file is not an executable", ret);
    // check if the elf file contains the correct target instruction set architecture (64-bit / for instructions)
    if (EM_X86_64 != elf_header->e_machine) JMP_W_CERROR("EFI file has the wrong instruction set architecture", ret);

    // next get the entrypoint (as a virtual address) of the program for it to start
    *bin_infos->entrypoint = elf_header->e_entry;  // this maybe zero

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
        THROW_ERROR("Failed to seek in file - possibly because its too large for fseeko to handle");
    const Elf64_Word phdrtsize = elf_header->e_phentsize * elf_header->e_phnum;
    Elf64_Phdr* phdrtable = calloc(1, phdrtsize);  // program header table
    bin_infos->prog_header_table = phdrtable;
    if (phdrtsize != fread(phdrtable, 1, phdrtsize, elf_file_stream))
        JMP_W_CERROR("Failed to read the program header table", ret);

    return 0;  // we assume if we came here everything is good :)
    ret:  // if we jumped here, something went wrong :(
    fclose(elf_file_stream);
    if (-errno == retval) return retval;  // if the errno code is still the same from the beginning, return it
    return -errno;  // else we just return the error code
}

int load_alloc_segments(const bin_info_table_T* bin_infos) {
    int retval = -EIO;  // we just make an I/O-Error the default here

    // iterate over the program header table and load the segments we need --> p_type=PT_LOAD
    for (Elf64_Half i = 0; i<bin_infos->elf_header->e_phnum; i++) {
        Elf64_Phdr phdr_entry = bin_infos->prog_header_table[i];  // get the next program header entry
        if (PT_LOAD != phdr_entry.p_type) continue;
        DEBUG("Found loadable segment at offset: %d\n", i);
    }
    goto ret;

    return 0;
    ret:
    if (-errno == retval) return retval;  // if the errno code is still the same from the beginning, return it
    return -errno;  // else we just return the error code
}

void cleanup(bin_info_table_T* bin_info) {
    free(bin_info->prog_header_table);
    bin_info->prog_header_table = nullptr;
    free(bin_info->elf_header);
    bin_info->elf_header = nullptr;
}

/**
 * Main function to start the loading and executing of the ELF binary
 *
 * @param argc
 * @param argv [1] The path and file name to the ELF binary
 */
int main(const int argc, char **argv) {
    DEBUG("Entering main");
    int retval = EXIT_SUCCESS;
    if (argc < 2) THROW_CUSTOM_ERROR("Usage: %s <path/to/ELF/binary>", *argv);

    bin_info_table_T binary_infos = {0};
    if (0 > open_and_parse_elf(&binary_infos, argv[1])) {
        PRINT_ERROR("Failed to load ELF header");
        goto on_error;
    }

    if (0 > load_alloc_segments(&binary_infos)) {
        PRINT_ERROR("Failed to load segments");
        goto on_error;
    }

    do_cleanup:
    cleanup(&binary_infos);
    return retval;
    on_error:
    retval = -EXIT_FAILURE;
    goto do_cleanup;
}
