"""
Simple Python script for testing the loader given a C-program.
A program here is NOT a compiled binary, but the programs C source code.
The binary itself is created by this program, so we can test both, PIEs and non-PIEs.

The syntax of calling this program is as follows:
test_loader.py {program/src/to/load.c} <arg1> <arg2> ... <argn>

For example:
test_loader.py PrintText.c foo bar 1234
"""

import os
import sys
import pathlib
import subprocess

build_path = "build/"

if __name__ == '__main__':
    if sys.argv.__len__() < 2 or sys.argv.__len__() >= 2 and not os.path.isfile(sys.argv[1]):
        print(f"Usage: {sys.argv[0]} " + "{program/src/to/load.c} <arg1> <arg2> ... <argn>", file=sys.stderr)
        exit()

    # compile the loader
    subprocess.run(
        ["cmake", "-S", ".", "-B", build_path], check=True
    )

    subprocess.run(
        ["cmake", "--build", build_path], check=True
    )
    if not os.path.isdir(build_path): os.mkdir(build_path)


    # create the test binaries
    test_src_file = pathlib.Path(sys.argv[1])
    test_binary = os.path.join(build_path, test_src_file.with_suffix('').stem)

    # compile the non PIE variant:
    text = f"| Testing {test_binary} as no PIE |"
    print(f"\n{'-' * (len(text)) + '\n'}{text}\n{'-' * (len(text)) + '\n'}")
    subprocess.run(['gcc', '-static', '-fno-PIE', '-no-pie', test_src_file, "-o", test_binary], check=True)
    subprocess.run(["./loader", test_binary, *sys.argv[2:]])

    # compile the PIE variant:
    text = f"| Testing {test_binary} as PIE |"
    print(f"\n{'-' * (len(text)) + '\n'}{text}\n{'-' * (len(text)) + '\n'}")
    subprocess.run(['gcc', '-fPIE', '-static-pie', test_src_file, "-o", test_binary], check=True)
    subprocess.run(["./loader", test_binary, *sys.argv[2:]])

    #os.rmdir(build_path)