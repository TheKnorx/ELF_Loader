cmake_minimum_required(VERSION 3.16)

project(loader C ASM_NASM)

enable_language(ASM_NASM)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/")

set(CMAKE_C_STANDARD 23)

add_executable(loader
        loader.c
        assembly_functions.asm
)

target_compile_options(loader PRIVATE
        $<$<COMPILE_LANGUAGE:C>:
        -Wall
        -Wextra
        -Werror
        -pedantic
        >
)

target_compile_definitions(loader PRIVATE
        FILE_OFFSET_BITS=64
        ENABLE_DEBUG
)