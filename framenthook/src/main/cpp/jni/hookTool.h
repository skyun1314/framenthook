#ifndef _HOOKTOOL_H
#define _HOOKTOOL_H
#include <sys/types.h> //pid_t¿‡–Õ
/*
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
*/
void* get_module_base( pid_t pid, const char* module_name );
#endif
