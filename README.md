# ELF_Loader
A simple implementation of a ELF binary loader, inspired by the 
[linux kernel function `load_elf_binary` at binfmt_elf.c](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c)

This loader is only intended for loading a simple* AMD-x86-64 EFI executable. Maybe, more features will be added in the future.

\* simple meaning the more complex the program gets in its operations, the more likely it is for the loader and consequently the program to fail. Failure might not even occur until after the loader has presumably successful loaded the program; - don't expect a full-blown, all edge-cases-fixing ELF loader 

### Comment style for functions:
```C
/*
* @param <parameter-name> {parameter-description}
* @param ...
* @return {return-description}
*/
```
