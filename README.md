# ELF_Loader
A simple implementation of a ELF binary loader, inspired by the 
[linux kernel function `load_elf_binary` at binfmt_elf.c](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c)

This loader is intended for loading a *simple*\* x86-64 EFI executable that fulfills the following requirements: 
- statically linked (gcc/ld: `-static`)
- no PIE (Position Independent Executable) at all (gcc: `-fno-PIE -no-pie` / ld explicitly: `-no-pie`)
- **or** static PIE (gcc: `-fPIE -static-pie` / ld explicitly: `-static -pie`)
- no dynamic PIE

\* *simple meaning the more complex the program gets in its operations, the more likely it is for the loader and consequently for the program to fail. Failure might not even occur until after the loader has presumably successfully loaded the program; - don't expect a full-blown, all edge-cases-fixing ELF loader!*

Support for dynamically linked executables (and therefore also for the ELF Interpreter `ld-linux`) or dynamic PIEs is not planned. 

<br>

---

<br>

## Commit `f27297c`
The loader in this and future versions now also supports loading a statically compiled Position-Independent-Executable. The cleanup-situation from before is fixed, (in theory) leaving no memory allocated after the loader transfers control to the loaded process image. 

## Commit `b3acf13`
The loader, as provided until this commit, is capable of loading gcc-compiled programs.
The program does end smoothly after the loaded process ends (due to gcc's exit routines); the caveat with this obviously being that the loader doesn't regain control after jumping into the new program, leaving memory still allocated and file-descriptors still open.

This commit yet again represents an even bigger milestone for the project, marking the completion of the foundation of the loader. As for now, every future commit will either be about fine-tuning, edge-case-handling or adding a new feature.

## Commit `6434421`
The loader in this commit supports loading pure (and simple) nasm programs. 
It **DOES NOT** end smoothly after the loaded process ends (process ends with SEGFAULT) and correct execution is not guaranteed nor fully tested yet!

This commit purely marks a milestone for the project: finally being able to see acceptable and visual results of the loaders successful working inner core. 

<br>

---

<br>

### Comment style for C-functions:
```C
/*
* {Description of the function}
* 
* @param <parameter-name> {parameter-description}
* @param ...
* @return {return-description}
*/
void foo(){...}
```

### Debugging
To enable debugging-messages in the program, pass the `ENABLE_DEBUG` flag via the `target_compile_definitions` in the 
`CMakeLists.txt` to the compiler. This is enabled by default.

### Testing
To test the loaders capability of loading certain C-programs, the python script under `src/test_loader.py` can be used. For detailed instructions on the usage, see the docstring in the beginning of the file itself. 
