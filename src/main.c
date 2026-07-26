// Includes
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include "common.h"

// Macros
#define ELF_HEADER_SIZE (sizeof(Elf64_Ehdr))
#define NOP __asm__("NOP")  // No-Operation - assembly instruction



/**
 * Function for opening and gathering information from the ELF binary, like checking its properties or
 * extracting header- and general information
 *
 * @param filename Path to and Filename of the ELF binary
 * @return I dont know yet
 */
void* open_and_init_elf(const char* filename) {
    DEBUG("Parsing elf file");

    // create a stdio file obj to the elf binary
    FILE* elf_file_stream = fopen(filename, "r");
    if (NULL == elf_file_stream) PRINT_ERROR("Failed to open the ELF binary");

    // get the elf file header
    Elf64_Ehdr* elf_header = calloc(1, ELF_HEADER_SIZE);
    if (NULL == elf_header) PRINT_ERROR("Failed to allocate space for the header-buffer");
    fread(elf_header, 1, ELF_HEADER_SIZE, elf_file_stream);

    NOP; NOP; NOP;

    return (void*)0xdeadbeef;
}

/**
 * Main function to start the loading and executing of the ELF binary
 *
 * @param argv [1] The path and file name to the ELF binary
 */
int main(const int argc, char **argv) {
    DEBUG("Entering main");
    if (argc < 2) THROW_CUSTOM_ERROR("Usage: %s <path/to/ELF/binary>", *argv);

    open_and_init_elf(argv[1]);
}
