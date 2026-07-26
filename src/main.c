#include <stdio.h>
#include <stdlib.h>

#include "common.h"

/**
 * Main function to start the loading and executing of the ELF binary
 * @param argv [1] The path and file name to the ELF binary
 */
int main(const int argc, char **argv) {
    if (argc < 2) THROW_CUSTOM_ERROR("Usage: %s <path/to/ELF/binary>", *argv);

    // ...
}
