#ifndef _SNOWGOTHOOK_H
#define _SNOWGOTHOOK_H
#include <elf.h>
typedef  struct{
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;

	Elf32_Dyn *dyn;
	Elf32_Word dynsz;

	Elf32_Sym *sym;
	Elf32_Word symsz;

	Elf32_Rel *relplt;
	Elf32_Word relpltsz;
	Elf32_Rel *reldyn;
	Elf32_Word reldynsz;

	uint32_t nbucket;
	uint32_t nchain;

	uint32_t *bucket;
	uint32_t *chain;

	const char *shstr;
	const char *symstr;
	uint8_t *elf_base;
}ElfInfo;


//这种是开辟空间存放原函数头文件，永久替换方式支持arm和thumb
void SnowGOTHook(unsigned int soBase,const char*symbol,void *newfun, void **result);

#endif