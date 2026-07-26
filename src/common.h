#pragma once  // add this in case its supported
#ifndef ELF_LOADER_COMMON_H
#define ELF_LOADER_COMMON_H

#include <stdio.h>
#include <stdlib.h>

#define THROW_CUSTOM_ERROR(FORMAT_STR, ...) do { \
    printf(FORMAT_STR, __VA_ARGS__);  \
    return EXIT_FAILURE;  \
} while (0);  // we should never get to this line

#endif //ELF_LOADER_COMMON_H