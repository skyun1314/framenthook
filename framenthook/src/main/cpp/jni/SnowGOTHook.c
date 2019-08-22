#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <jni.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "SnowGOTHook.h"
#include "common.h"
#define PAGE_START(addr) (~(getpagesize() - 1) & (addr))
#define R_ARM_ABS32 0x02
#define R_ARM_GLOB_DAT 0x15
#define R_ARM_JUMP_SLOT 0x16

#define SAFE_SET_VALUE(t, v) if(t) *(t) = (v)

//得到hash值
unsigned int ccelf_hash(const char *name) {
	const unsigned char *tmp = (const unsigned char *) name;
	unsigned h = 0, g;

	while (*tmp) {
		h = (h << 4) + *tmp++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}
void findSymByName(ElfInfo *info, const char *symbol, Elf32_Sym **sym, int *symidx) {
	Elf32_Sym *target = NULL;

	unsigned int hash = ccelf_hash(symbol);//symbol为要找的符号
	uint32_t index = info->bucket[hash % info->nbucket];
	//info->sym其实是dynsym节内容
	if (!strcmp(info->symstr + info->sym[index].st_name, symbol)) {
		target = info->sym + index;
	}

	if (!target) {
		do {
			index = info->chain[index];
			if (!strcmp(info->symstr + info->sym[index].st_name, symbol)) {
				target = info->sym + index;
				break;
			}

		} while (index != 0);
	}

	if(target)
	{
		if(sym)
		{
			*(sym) = (target);
		}
		if(symidx)
		{
			*(symidx) = (index);
		}
	}
}
//找到节根据类型
static inline Elf32_Phdr *findSegmentByType(ElfInfo *info, const Elf32_Word type)
{
	Elf32_Phdr *target = NULL;
	LOGE("----段首地址=%x--",info->phdr);//74d66034
	Elf32_Phdr *phdr = info->phdr;
	int i;
	LOGE("--------段数量=%x--",info->ehdr->e_phnum);//8
	for(i=0; i<info->ehdr->e_phnum; i++){
		if(phdr[i].p_type == type){
			LOGE("---i=%x-type%x-",i,type);//i=4-type2-
			target = phdr + i;
			break;
		}
	}
	LOGE("---找到目标segment节首地址-target=%x----",target);//0x74d660b4
	return target;
}
static void getSegmentInfo(ElfInfo *info, const Elf32_Word type, Elf32_Phdr **ppPhdr, Elf32_Word *pSize, Elf32_Addr *data){
	Elf32_Phdr *_phdr = findSegmentByType(info, type);
	//-找到目标segment节首地址-_phdr=74d680b4--段内容偏移=_phdr->p_vaddr=644d68-
	LOGE("---找到目标segment节首地址-_phdr=%x--段内容偏移=_phdr->p_vaddr=%x--",_phdr,_phdr->p_vaddr);//0x74d660b4
	if(_phdr){
		 //从内存读取
		
		if(data) 
		{
			//.dynamic段内容内存中偏移=753acd68
			LOGE("-----.dynamic段内容内存中偏移=%x",info->elf_base + _phdr->p_vaddr);
			*data=(Elf32_Addr*)(info->elf_base + _phdr->p_vaddr);
		}
		if(pSize)
		{
			LOGE("-=-----.dynamic段内容的大小=%x",_phdr->p_memsz);
			*pSize=_phdr->p_memsz;
		}
	}
	else{
		LOGE("[-] Could not found segment type is %d\n", type);
	}
	if(ppPhdr)
	{
		*(ppPhdr)=_phdr;
	}
}

void getElfInfoBySegmentView(ElfInfo *info,unsigned int soBase){
	LOGE("--0-soBase=%x----",soBase);
	//奇葩的类型转换，注意哦，这里必须是uint8_t不然，下面+ehdr->e_phoff就会出现奇怪情况
	info->elf_base = (uint8_t *)soBase;
	
	
	info->ehdr =(Elf32_Ehdr *)(info->elf_base);
	// may be wrong
	LOGE("--2--info->ehdr->e_shoff=%x--info->ehdr->e_phoff=%x-",info->ehdr->e_shoff,info->ehdr->e_phoff);
	info->shdr =(Elf32_Shdr *)(info->elf_base + info->ehdr->e_shoff);//节的信息可能被抹掉了
	info->phdr =(Elf32_Phdr *)(info->elf_base +info->ehdr->e_phoff);//这个是没法抹掉的
	LOGE("3---info->phdr=%x",info->phdr);
	info->shstr = NULL;
	Elf32_Addr m_p_vaddr;
	Elf32_Phdr *dynamic = NULL;
	Elf32_Word size = 0;

	getSegmentInfo(info, PT_DYNAMIC, &dynamic,&size,&m_p_vaddr);
	info->dyn=m_p_vaddr;
	
	LOGE("------.dynamic size=%x--.dynamic content off=%x",size,info->dyn);
	
	if(!dynamic){
		LOGE("[-] could't find PT_DYNAMIC segment");
	
	}
	info->dynsz = size / sizeof(Elf32_Dyn);

	Elf32_Dyn *dyn = info->dyn;
	int i;
	for(i=0; i<info->dynsz; i++, dyn++){

		switch(dyn->d_tag){

		case DT_SYMTAB:
			info->sym = (Elf32_Sym *)(info->elf_base + dyn->d_un.d_ptr);
			break;

		case DT_STRTAB:
			info->symstr = (const char *)(info->elf_base + dyn->d_un.d_ptr);
			break;
		////DT_REL=17 .rel.dyn节
		case DT_REL:
			info->reldyn = (Elf32_Rel *)(info->elf_base + dyn->d_un.d_ptr);
			break;
		//DT_REL=17 .rel.dyn节大小
		case DT_RELSZ:
			info->reldynsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;
		//DT_JMPREL=23 .rel.plt节
		case DT_JMPREL:
			info->relplt = (Elf32_Rel *)(info->elf_base + dyn->d_un.d_ptr);
			break;
		////DT_PLTRELSZ=2 .rel.plt节大小
		case DT_PLTRELSZ:
			info->relpltsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;

		case DT_HASH:
			{
				uint32_t *rawdata = (uint32_t *)(info->elf_base + dyn->d_un.d_ptr);
				info->nbucket = rawdata[0];
				info->nchain = rawdata[1];
				info->bucket = rawdata + 2;
				info->chain = info->bucket + info->nbucket;

				info->symsz = info->nchain;
			}
			break;
		}
	}

}
static int modifyMemAccess(void *addr, int prots){
	void *page_start_addr = (void *)PAGE_START((uint32_t)addr);
	return mprotect(page_start_addr, getpagesize(), prots);
}
static int clearCache(void *addr, size_t len){
	void *end = (uint8_t *)addr + len;
	syscall(0xf0002, addr, end);
}
static int replaceFunc(void *addr, void *replace_func, void **old_func){
	int res = 0;
	//0x1EB5,哈哈这个是我们要替成的函数首地址哟，也就是my_strlen的首地址
		LOGE("-----will replace-func addr=%x-------\n",(int)replace_func);//-will replace-func addr=78638ed1
	
	if(*(void **)addr == replace_func){
		LOGE("addr %p had been replace.", addr);
		goto fails;
	}

	if(!*old_func){
		*old_func = *(void **)addr;
	}

	if(modifyMemAccess((void *)addr, PROT_EXEC|PROT_READ|PROT_WRITE)){
		//LOGE("[-] modifymemAccess fails, error %s.", strerror(errno));
		res = 1;
		goto fails;
	}

	*(void **)addr = replace_func;
	clearCache(addr, getpagesize());
	//LOGE("[+] old_func is %p, replace_func is %p, new_func %p.", *old_func, replace_func, *(uint32_t *)addr);

	fails:
	return res;
}
void SnowGOTHook(unsigned int soBase,const char*symbol,void *newfun, void **result)
{
	LOGE("-------soBase=%x---symbol=%s----",soBase,symbol);
	ElfInfo info;
	//根据base获取，dynstr，dynsym，hash节和(rel.dyn,rel.plt节内容和大小)
	getElfInfoBySegmentView(&info, soBase);
	Elf32_Sym *sym = NULL;
	int symidx = 0;
//找函数符号，sym是dynsym节内容里面第symidx个项，其st_name作为索引就可以在dynstr节里面找到
//我们的要hook的函数
	findSymByName(&info, symbol, &sym, &symidx);
	if(!sym){
		LOGE("[-] Could not find symbol %s", symbol);
		//goto fails;
	}else{
		LOGE("[+] sym %p, symidx %d.", sym, symidx);
	}
	//relpltsz是.rel.plt节大小
	//#define ELF32_R_SYM(x) ((x) >> 8)
	//#define ELF32_R_TYPE(x) ((x) & 0xff)
	//#define R_ARM_JUMP_SLOT	22	/* Create PLT entry */
	//SHT_INIT_ARRAY
	
	//你用readelf -a可以看到.rel.plt会看到的
	int i;
	for (i= 0; i < info.relpltsz; i++) {
		Elf32_Rel rel = info.relplt[i];
		//当直接调用外部函数时
		if (ELF32_R_SYM(rel.r_info) == symidx && ELF32_R_TYPE(rel.r_info) == R_ARM_JUMP_SLOT) {
			//elf_base是base。窝巢rel.r_offset居然放着函数地址,雷人啊啊啊
			void *addr = (void *) (info.elf_base + rel.r_offset);
			//-find1 funaddr=7863bfdc--ida_addr=4fdc
			LOGE("-----find1 funaddr=%x--ida_addr=%x",(int)addr,(int)addr-(int)info.elf_base);
			if (replaceFunc(addr, newfun, result))
				//goto fails;

			//only once
			break;
		}
	}
	//reldynsz是.rel.dyn节大小
	//#define R_ARM_ABS32	2	/* Direct 32 bit  */
	//#define R_ARM_GLOB_DAT	21	/* Create GOT entry */

	for (i = 0; i < info.reldynsz; i++) {
		Elf32_Rel rel = info.reldyn[i];
		if (ELF32_R_SYM(rel.r_info) == symidx &&
				(ELF32_R_TYPE(rel.r_info) == R_ARM_ABS32
						|| ELF32_R_TYPE(rel.r_info) == R_ARM_GLOB_DAT)) 
						{
			LOGE("--(ELF32_R_TYPE(rel.r_info)=%d----",(ELF32_R_TYPE(rel.r_info)));//2=R_ARM_ABS32
			void *addr = (void *) (info.elf_base + rel.r_offset);//0x5008和0x500C，
			//输出两次，均是R_ARM_ABS32类型，其中int)addr-(int)info->elf_base依次为0x500C和0x5008
			//两次打印的结果如下，原来0x500C和0x5008存放着是，strlen这个函数在内存的地址呢
			//find2 funaddr=4008af85--ida_addr=cb517f85
			//find2 funaddr=4008af85--ida_addr=cb517f85
			LOGE("-----find2 funaddr=%x--ida_addr=%x",(int)addr,(int)addr-(int)info.elf_base);
		
			if (replaceFunc(addr, newfun, result))
			{
				//goto fails;
			}
		}
	}
}