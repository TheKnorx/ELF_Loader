// Includes
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <iso646.h>
#include <string.h>

#include "common.h"

// Macros
#define ELF_HEADER_SIZE (sizeof(Elf64_Ehdr))
#define NOP __asm__("NOP")  // No-Operation - assembly instruction

typedef struct elf_info_table_S {
    Elf64_Ehdr elf_header;
    Elf64_Phdr prog_header;
} elf_info_table_T;


/**
 * Function for opening and gathering information from the ELF binary, like checking its properties or
 * extracting header- and general information
 *
 * @param bin_infos Pointer to data field for storing the return values of this function
 * @param filename Path to and Filename of the ELF binary
 */
void open_and_parse_elf(elf_info_table_T* bin_infos, const char* filename) {
    DEBUG("Parsing elf file");

    // create a stdio file obj to the elf binary
    FILE* elf_file_stream = fopen(filename, "r");
    if (NULL == elf_file_stream) PRINT_ERROR("Failed to open the ELF binary");

    // get the elf file header
    Elf64_Ehdr* elf_header = calloc(1, ELF_HEADER_SIZE);
    if (NULL == elf_header) PRINT_ERROR("Failed to allocate space for the header-buffer");
    fread(elf_header, 1, ELF_HEADER_SIZE, elf_file_stream);

    // check if it's really an ELF binary
    if (not memcmp(ELFMAG, elf_header->e_ident, SELFMAG)) goto ret;

    NOP; NOP; NOP;
    ret:
    free(elf_header);
    fclose(elf_file_stream);
}

/**
 * Main funcstion to start the loading and executing of the ELF binary
 *
 * @param argc
 * @param argv [1] The path and file name to the ELF binary
 */
int main(const int argc, char **argv) {
    DEBUG("Entering main");
    if (argc < 2) THROW_CUSTOM_ERROR("Usage: %s <path/to/ELF/binary>", *argv);

    elf_info_table_T binary_infos = {};
    open_and_parse_elf(&binary_infos, argv[1]);

}
