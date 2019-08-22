#ifndef _SNOWINLINEHOOK_H
#define _SNOWINLINEHOOK_H
//这种是开辟空间存放原函数头文件，永久替换方式支持arm和thumb
void SnowInlineHook(unsigned int symbol, void *replace, void **result);

#endif
