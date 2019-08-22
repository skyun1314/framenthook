#ifndef _SNOWINLINESIMPLEHOOK_H
#define _SNOWINLINESIMPLEHOOK_H
struct hook_t {
	unsigned int jump[3];
	unsigned int store[3];
	unsigned char jumpt[20];
	unsigned char storet[20];
	unsigned int orig;
	unsigned int patch;
	unsigned char thumb;
	unsigned char name[128];
	void *data;
};
void hook_precall(struct hook_t *h);
void hook_postcall(struct hook_t *h);
//这是不停修改头部的hook方式,支持arm和thumb
void SnowInlineSimpleHook (struct hook_t *h,unsigned long int symbol, void *replace, void **result);
#endif