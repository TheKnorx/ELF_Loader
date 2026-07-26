#pragma once  // add this in case its supported
#ifndef ELF_LOADER_COMMON_H
#define ELF_LOADER_COMMON_H

#include <stdio.h>
#include <stdlib.h>

// As a variadic argument we except format specifier for printf
#define THROW_CUSTOM_ERROR(FORMAT_STR, ...) do { \
    printf(FORMAT_STR, ##__VA_ARGS__);  \
    exit(EXIT_FAILURE);  \
} while (0);  // we should never get to this line

// As the variadic argument we except an error code - can be left out
#define PRINT_ERROR(INFO_STR, ...) do {  \
    perror(INFO_STR);  \
    exit(__VA_OPT__(+ 1 +) EXIT_FAILURE);  \
} while (0);  // we should never get to this line

#define DEBUG(FORMAT_STR, ...) {printf(FORMAT_STR, ##__VA_ARGS__); putchar('\n');}



#endif //ELF_LOADER_COMMON_H