#include "SnowInlineSimpleHook.h"
#include "common.h"
#define PAGE_START(X)   ( (X) & PAGE_MASK )
#include <sys/mman.h>
#include "SnowInlineHook.h"
int changeMemory(int symbolAddr)
{
	//都修改了一个页了，估计那20个字节在这个范围内
	int result= mprotect((const void *)(PAGE_START(symbolAddr)),PAGE_SIZE,PROT_EXEC|PROT_READ|PROT_WRITE );
    if(!result)
    {
		LOGE("-----change memory success----\n");
		return 1;
	//哎懒得去掉可写
    //result = mprotect((const void *)(change_addr&PAGE_MASK),sysconf(_SC_PAGESIZE), PROT_EXEC|PROT_READ);//改回去
    }
	return 0;
}

void SnowInlineSimpleHook(struct hook_t *h,unsigned long int symbol, void *replace, void **result)
{
	unsigned long int addr;
	int i;
	changeMemory(symbol);
	addr=symbol;
	LOGE("我们将要hook的函数地址=%x",addr);
	if (addr % 4 == 0) {
		LOGE("ARM using 0x%lx\n", (unsigned long)replace);
		h->thumb = 0;
		h->patch = (unsigned int)replace;
		h->orig = addr;
		h->jump[0] = 0xe59ff000; // LDR pc, [pc, #0]
		h->jump[1] = h->patch;
		h->jump[2] = h->patch;
		for (i = 0; i < 3; i++)
		{
			h->store[i] = ((int*)h->orig)[i];
			LOGE("----((int*)h->orig)[%d]=%x\n",i,((int*)h->orig)[i]);
		}
			
		for (i = 0; i < 3; i++)
		{
			((int*)h->orig)[i] = h->jump[i];
			LOGE("----h->jump[%d]=%x\n",i,h->jump[i]);
		}
	}
	else {
		if ((unsigned long int)result % 4 == 0)
			LOGE("warning hook is not thumb 0x%lx\n", (unsigned long)result);
		h->thumb = 1;
		LOGE("THUMB using 0x%lx\n", (unsigned long)result);
		h->patch = (unsigned int)replace;
		h->orig = addr;	
		h->jumpt[1] = 0xb4;
		h->jumpt[0] = 0x60; // push {r5,r6}
		h->jumpt[3] = 0xa5;
		h->jumpt[2] = 0x03; // add r5, pc, #12
		h->jumpt[5] = 0x68;
		h->jumpt[4] = 0x2d; // ldr r5, [r5]
		h->jumpt[7] = 0xb0;
		h->jumpt[6] = 0x02; // add sp,sp,#8
		h->jumpt[9] = 0xb4;
		h->jumpt[8] = 0x20; // push {r5}
		h->jumpt[11] = 0xb0;
		h->jumpt[10] = 0x81; // sub sp,sp,#4
		h->jumpt[13] = 0xbd;
		h->jumpt[12] = 0x20; // pop {r5, pc}
		h->jumpt[15] = 0x46;
		h->jumpt[14] = 0xaf; // mov pc, r5 ; just to pad to 4 byte boundary
		memcpy(&h->jumpt[16], (unsigned char*)&h->patch, sizeof(unsigned int));
		unsigned int orig = addr - 1; // sub 1 to get real address
		for (i = 0; i < 20; i++) {
			h->storet[i] = ((unsigned char*)orig)[i];
			//log("%0.2x ", h->storet[i])
		}
		//log("\n")
		for (i = 0; i < 20; i++) {
			((unsigned char*)orig)[i] = h->jumpt[i];
			//log("%0.2x ", ((unsigned char*)orig)[i])
		}
	}
	hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
}

void hook_precall(struct hook_t *h)//修改函数前部
{
	int i;
	
	if (h->thumb) {
		unsigned int orig = h->orig - 1;
		for (i = 0; i < 20; i++) {
			((unsigned char*)orig)[i] = h->storet[i];
		}
	}
	else {
		for (i = 0; i < 3; i++)
		{
			((int*)h->orig)[i] = h->store[i];
			LOGE("----h->store[%d]=%x\n",i,h->store[i]);
		}
	}	
	hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
}

void hook_postcall(struct hook_t *h)//恢复函数前部
{
	int i;
	
	if (h->thumb) {
		unsigned int orig = h->orig - 1;
		for (i = 0; i < 20; i++)
			((unsigned char*)orig)[i] = h->jumpt[i];
	}
	else {
		for (i = 0; i < 3; i++)
		{
			((int*)h->orig)[i] = h->jump[i];
			LOGE("----h->jump[%d]=%x\n",i,h->jump[i]);
		}
	}
	hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));	
}