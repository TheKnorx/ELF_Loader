#pragma once  // add this in case its supported
#ifndef ELF_LOADER_COMMON_H
#define ELF_LOADER_COMMON_H

#include <stdio.h>
#include <stdlib.h>

// extern assembly functions
extern void transfer_control(void* entry_point, void* stack_addr);
extern void *memset_(void* s, int c, size_t n);
extern ssize_t memcpy_n(void* dest, const void* src);


#define NOP __asm__("NOP")  // No-Operation - assembly instruction

/**
 * Macro 'functions'
 * All macros that have the word `THROW` in them, call the exit() function
 * Otherwise, they let the program continue - errno is always preserved then
 */

#define PRESERVER_ERRNO int _errno_saved = errno;  // for preserving the errno value in a block
#define RESTORE_ERRNO errno = _errno_saved;  // for restoring the errno value from the previously preserved one

/* Throw a custom error message and exit
 * As the variadic arguments the format specifier for printf can be specified */
#define THROW_CUSTOM_ERROR(FORMAT_STR, ...) do { \
    fprintf(stderr, FORMAT_STR, ##__VA_ARGS__);  \
    putc('\n', stderr);  \
    exit(EXIT_FAILURE);  \
} while (0);  // we should never get to this line

// Print a custom error message, followed by the errno code
#define PRINT_ERROR(INFO_STR) do {  \
    PRESERVER_ERRNO  \
    perror(INFO_STR);  \
    RESTORE_ERRNO  \
} while (0);

/* Print a custom error message and continue with the program
* As the variadic arguments the format specifier for printf can be specified */
#define PRINT_CUSTOM_ERROR(FORMAT_STR, ...) do { \
    PRESERVER_ERRNO  \
    fprintf(stderr, FORMAT_STR, ##__VA_ARGS__);  \
    putc('\n', stderr);  \
    RESTORE_ERRNO  \
} while (0);

/* Prints debug information
 * As the variadic arguments the format specifier for printf can be specified */
#define DEBUG(FORMAT_STR, ...) {printf(FORMAT_STR, ##__VA_ARGS__); putchar('\n');}

/* Push a value VAL onto the stack, pointed to by the stack pointer SP and increment SP by 8-Bytes!
 * SP moves *downwards*!! - this macro shall not be used for traditional stack pushing!
 * All pushed values will be cast to 8-Bytes values */
#define PUSH(VAL, SP) {*SP = (Elf64_Xword)VAL; SP = (Elf64_Xword*)((Elf64_Xword)SP + POINTER_SIZE);}

/* Align a stack pointer to be: SP (mod 16) = 0 */
#define ALIGN_SP(SP) {SP = (Elf64_Xword*)((Elf64_Xword)SP + 16 - (Elf64_Xword)SP % 16);}

// For 'converting' a macro tag to a string - e.g. for debugging, etc...
#define M_TO_STR(M) #M

// I know those macro are of bad coding style, but it also helps massively in reducing duplicate code, so I take it
#define JMP_W_CERROR(ERROR_STR, JMP_LABEL, ...) { PRINT_CUSTOM_ERROR(ERROR_STR __VA_OPT__(,) __VA_ARGS__); goto JMP_LABEL; }
#define JMP_W_ERROR(ERROR_STR, JMP_LABEL) { PRINT_ERROR(ERROR_STR); goto JMP_LABEL; }

/* Macros for getting the MIN/MAX value of two values, VAL1 and VAL2 */
#define MIN(VAL1, VAL2) ( (VAL1) < (VAL2) ? (VAL1) : (VAL2) )
#define MAX(VAL1, VAL2) ( (VAL1) > (VAL2) ? (VAL1) : (VAL2) )

/* Align an address to a given page up the address range or down */
#define ALIGN_TO_PAGE_DOWN(ADDR, PAGESIZE) ((ADDR) - (ADDR) % (PAGESIZE))
#define ALIGN_TO_PAGE_UP(ADDR, PAGESIZE) ((ADDR) + (ADDR) % (PAGESIZE))

/* This is the standard start of every function - it resets errno
 */
#define STANDARD_FUNCTION_START errno = 0;

/* This is the standard ending of every function.
 * On success, it returns 0. Otherwise, if errno was set, errno is returned, else RETVAL_DEFAULT is returned
 */
#define STANDARD_FUNCTION_RETURN(RETVAL_DEFAULT) \
    return 0;  /* we assume if we came here everything is good */  \
    ret:  \
    if (!errno) return RETVAL_DEFAULT;  /* if errno is cleared, RETVAL_DEFAULT */  \
    return -errno;  /* else return errno */  \


/** Constants */
#define ELF_HEADER_SIZE (sizeof(Elf64_Ehdr))
#define DEFAULT_STACK_SIZE (8 * 1024 * 1024)
#define POINTER_SIZE sizeof(Elf64_Addr*)



#endif //ELF_LOADER_COMMON_H