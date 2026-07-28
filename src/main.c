// Includes
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <iso646.h>
#include <string.h>

#include "common.h"

// Macros
#define ELF_HEADER_SIZE (sizeof(Elf64_Ehdr))
#define NOP __asm__("NOP")  // No-Operation - assembly instruction
#define GET_PHDR_ENTRY(_e_phoff, _e_phentsize) (_e_phoff + i * _e_phentsize)

typedef struct bin_info_table_S {
    Elf64_Ehdr* elf_header;
    Elf64_Phdr* prog_header_table;
} bin_info_table_T;


/**
 * Function for opening and gathering information from the ELF binary, like checking its properties or
 * extracting header- and general information
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
    const long file_size = ftell(elf_file_stream);
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

    /* Do consistency-checks to make sure it's really a valid ELF file */
    // check the ELF magic number
    if (0 != memcmp(ELFMAG, elf_header->e_ident, SELFMAG)) goto ret;
    if (!elf_header->e_phoff) {
        PRINT_CUSTOM_ERROR("Program header table size if 0");
        goto ret;
    }
    if (elf_header->e_phoff > file_size) {
        PRINT_CUSTOM_ERROR("Program header table is beyond EOF");
        goto ret;
    }

    // next get the program header table
    fseeko(elf_file_stream, elf_header->e_phoff, SEEK_SET);
    const Elf64_Word phdrtsize = elf_header->e_phentsize * elf_header->e_phnum;
    Elf64_Phdr* phdrtable = calloc(1, phdrtsize);  // program header table
    bin_infos->prog_header_table = phdrtable;
    if (phdrtsize != fread(phdrtable, 1, phdrtsize, elf_file_stream)) {
        PRINT_CUSTOM_ERROR("Failed to read the program header table");
        goto ret;
    }

    return 0;  // we assume if we came here everything is good
    ret:  // if we jumped here, something went wrong :(
    fclose(elf_file_stream);
    if (-errno == retval) return retval;  // if the errno code is still the same from the beginning, return it
    return -errno;  // else we just return the error code
}

int load_alloc_segments(bin_info_table_T bin_infos) {
    int retval = -EIO;  // we just make an I/O-Error the default here

    //...

    return 0;
    ret:
    if (-errno == retval) return retval;  // if the errno code is still the same from the beginning, return it
    return -errno;  // else we just return the error code
}

void cleanup(const bin_info_table_T* bin_info) {
    free(bin_info->prog_header_table);
    free(bin_info->elf_header);
}

/**
 * Main function to start the loading and executing of the ELF binary
 *
 * @param argc
 * @param argv [1] The path and file name to the ELF binary
 */
int main(const int argc, char **argv) {
    DEBUG("Entering main");
    if (argc < 2) THROW_CUSTOM_ERROR("Usage: %s <path/to/ELF/binary>", *argv);

    bin_info_table_T binary_infos = {0};
    if (open_and_parse_elf(&binary_infos, argv[1]) < 0) THROW_ERROR("Failed to get ELF header information")


    cleanup(&binary_infos);
}
