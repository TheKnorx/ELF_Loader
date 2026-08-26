cmake_minimum_required(VERSION 3.16)

project(main C ASM_NASM)

enable_language(ASM_NASM)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/")

set(CMAKE_C_STANDARD 23)

add_executable(main
        main.c
        assembly_functions.asm
)

target_compile_options(main PRIVATE
        $<$<COMPILE_LANGUAGE:C>:
        -Wall
        -Wextra
        -Werror
        -pedantic
        -DDEBUG
        >
)

target_compile_definitions(main PRIVATE
        FILE_OFFSET_BITS=64
)