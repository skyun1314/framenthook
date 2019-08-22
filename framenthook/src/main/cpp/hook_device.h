#include <jni.h>
#include <string>
#include <dlfcn.h>

# include <stdlib.h>
#include <zlib.h>
#include <android/log.h>
#include <sys/types.h>
#include <unistd.h>
#include<vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include<cstring>
#include <pthread.h>
#include <stdio.h>
#include <sys/system_properties.h>
#include <stdlib.h>
#include "MSHook/Hooker.h"

#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,"wodelog", __VA_ARGS__)

char propValue_all[PROP_VALUE_MAX] = {0};


int (*old__system_property_read)(int pi, char *name, char *value);

int new__system_property_read(int pi, char *name, char *value) {
    int result;
    if (strcmp(propValue_all, "ro.debuggable") == 0) {
        strcpy(value, "0");
    } else if (strcmp(propValue_all, "persist.service.bdroid.bdaddr") == 0) {
        strcpy(value, "88:77:66:55");
    } else if (strcmp(propValue_all, "ro.boot.serialno") == 0 ||
               strcmp(propValue_all, "ro.serialno") == 0) {
        strcpy(value, "aaaaab2c43a8b14e");
    } else if (strcmp(propValue_all, "net.hostname") == 0) {
        strcpy(value, "android-e8aaef782ac9aaaa");
    } else {
        result = old__system_property_read(pi, name, value);
    }
    result = strlen(value);

    LOGD("hook result(%d) system_property_read(%s): %s ", result, propValue_all, value);
    return result;
}


int (*old__system_property_find)(const char *name);

int new__system_property_find(const char *name) {
    memset(propValue_all, 0, PROP_VALUE_MAX);
    strcpy(propValue_all, name);
    return old__system_property_find(name);
}

int (*old__system_property_get)(char *name, char *value);

int new__system_property_get(char *name, char *value) {
    int result = old__system_property_get(name, value);
    //   LOGD("hook system_property_get：%s : %s ", name, value);
    return result;
}

void hook_device() {
 /*   Cydia::MSHookFunction("libc.so",  "__system_property_read", (  void *) &new__system_property_read, (void **) &old__system_property_read);
    Cydia::MSHookFunction("libc.so",  "__system_property_find", (  void *) &new__system_property_find, (void **) &old__system_property_find);
    Cydia::MSHookFunction("libc.so",  "__system_property_get", (   void *) &new__system_property_get, (void **) &old__system_property_get);
*/
    char propValue[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.boot.serialno", propValue);


LOGD("serial:%s", propValue);

    memset(propValue, 0, PROP_VALUE_MAX);
    __system_property_get("ro.serialno", propValue);
 LOGD("serial:%s", propValue);


    memset(propValue,
           0, PROP_VALUE_MAX);
    __system_property_get("net.hostname", propValue);
 LOGD("android_id:%s", propValue);

    memset(propValue,
           0, PROP_VALUE_MAX);
    __system_property_get("persist.service.bdroid.bdaddr", propValue);
    LOGD("mac:%s", propValue);


    memset(propValue,
           0, PROP_VALUE_MAX);
    const prop_info *pi = __system_property_find("persist.service.bdroid.bdaddr");
    if (pi != 0) {
        __system_property_read(pi,
                               0, propValue);
        LOGD("mac:%s", propValue);
    }
    memset(propValue,  0, PROP_VALUE_MAX);
    __system_property_get("phone.imei",propValue);
    LOGD("imei:%s", propValue);

}