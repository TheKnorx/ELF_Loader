#pragma once  // add this in case its supported
#ifndef ELF_LOADER_COMMON_H
#define ELF_LOADER_COMMON_H

#include <stdio.h>
#include <stdlib.h>

#define PRESERVER_ERRNO int _errno_saved = errno;
#define RESTORE_ERRNO errno = _errno_saved;

// As a variadic argument we except format specifier for printf
#define THROW_CUSTOM_ERROR(FORMAT_STR, ...) do { \
    printf(FORMAT_STR, ##__VA_ARGS__);  \
    exit(EXIT_FAILURE);  \
} while (0);  // we should never get to this line

// As the variadic argument we except an error code - can be left out
#define THROW_ERROR_DEPRECATED(INFO_STR, ...) do {  \
    perror(INFO_STR);  \
    exit(__VA_OPT__(+ 1 +) EXIT_FAILURE);  \
} while (0);  // we should never get to this line

#define PRINT_ERROR(INFO_STR) do {  \
    PRESERVER_ERRNO  \
    perror(INFO_STR);  \
    RESTORE_ERRNO  \
} while (0);

// As a variadic argument we except format specifier for printf
#define PRINT_CUSTOM_ERROR(FORMAT_STR, ...) do { \
    PRESERVER_ERRNO  \
    fprintf(stderr, FORMAT_STR, ##__VA_ARGS__);  \
    putc('\n', stderr);  \
    RESTORE_ERRNO  \
} while (0);

#define DEBUG(FORMAT_STR, ...) {printf(FORMAT_STR, ##__VA_ARGS__); putchar('\n');}



#endif //ELF_LOADER_COMMON_H