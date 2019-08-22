//
// Created by 赵凯 on 2018/5/10.
//

#ifndef HOOKTEST_JNIHOOK_H
#define HOOKTEST_JNIHOOK_H


#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <unwind.h>
#include "Object.h"
#include "MSHook/Hooker.h"
#include <jni.h>
#include <string>

#include "MSHook/Hooker.h"
#include "MSHook/util.h"
#include "art.h"
#include "jni/hookTool.h"

#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <unwind.h>
#include<android/log.h>
#define LOGI(...)  __android_log_print(ANDROID_LOG_DEBUG,"wodelog", __VA_ARGS__)



char * libJpush="libJpush.so";

void *get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    // 1. 生成一个进程maps目录
    if (pid < 0) {
        /* self process */
        strcpy(filename, "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    // 2. 打开文件，读取文件内容, 找到模块
    // 2.1 打开文件
    fp = fopen(filename, "r");

    if (fp != NULL) {
        // 2.2 循环读取文件内容
        while (fgets(line, sizeof(line), fp)) {
            // 2.3 找到模块
            //  LOGI("查找模块:%s", line);
            if (strstr(line, module_name)) {
                LOGI("找到模块基值了：%s",line);
                // 2.4 提取模块基地址
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                if (addr == 0x8000) addr = 0;

                break;
            }
        }
        // 2.5 关闭文件指针
        fclose(fp);
    } else {
        LOGI("打开文件失败：%s", filename);
    }

    return (void *) addr;
}


char *MAKE_ARG_ARRAY(char *str, va_list args, Method *method) {
   /* LOGI("进入MAKE_ARG_ARRAY1%s",method->clazz->descriptor);
    LOGI("进入MAKE_ARG_ARRAY2%s", method->name);
    LOGI("进入MAKE_ARG_ARRAY3%s",(method->shorty) + 1);
    LOGI("进入MAKE_ARG_ARRAY4%c",(method->shorty)[0]);
    char buffer[200];



    sprintf(buffer, "%s : %s%s(%s)%c   ", str, method->clazz->descriptor, method->name, (method->shorty) + 1, (method->shorty)[0]);
    LOGI("buffer1: %s",buffer);
    int argc = strlen(method->shorty); // dexProtoGetParameterCount(&method->prototype);
    LOGI("argc: %d",argc);
    */
    int argc=3;
    int i;
    char buffer[200];
    sprintf(buffer, "%s [%x]: ", str,method);
    char buffer_tmp[200];
// env->NewObject(AppBindData,init,1,env->NewStringUTF("haha"),5);
    jvalue *argarray = (jvalue *) alloca(argc - 1 * sizeof(jvalue));
    for (i = 1; i < argc; i++) {

        switch ('I'/*method->shorty[i]*/) {
            case 'Z':

            case 'B':

            case 'S':

            case 'C':

            case 'I':
                argarray[i].i = va_arg(args, jint);
                sprintf(buffer_tmp, " %d ,", argarray[i].i);

                break;
            case 'J':
                argarray[i].j = va_arg(args, jlong);
                sprintf(buffer_tmp, " %lld ,", argarray[i].j);
                break;
            case 'L':
                argarray[i].l = va_arg(args, jobject);
                sprintf(buffer_tmp, " %x ,",* argarray[i].l);
                break;
            case 'D':
                argarray[i].d = va_arg(args, double);
                sprintf(buffer_tmp, " %lf ,", argarray[i].d);
                break;
            case 'F':
                argarray[i].f = (float) va_arg(args, double);
                sprintf(buffer_tmp, " %lf ,", argarray[i].f);
                break;
        }
        strcat(buffer, buffer_tmp);
    }

    return buffer;
    /*char *str1="%s[%s]";
    return str;*/
}


struct BacktraceState {
    intptr_t *current;
    intptr_t *end;
};


static _Unwind_Reason_Code unwindCallback(struct _Unwind_Context *context, void *arg) {
    BacktraceState *state = static_cast<BacktraceState *>(arg);
    intptr_t ip = (intptr_t) _Unwind_GetIP(context);
    if (ip) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            state->current[0] = ip;
            state->current++;
        }
    }
    return _URC_NO_REASON;
}

size_t captureBacktrace(intptr_t *buffer, size_t maxStackDeep) {
    BacktraceState state = {buffer, buffer + maxStackDeep};
    _Unwind_Backtrace(unwindCallback, &state);
    return state.current - buffer;
}

void dumpBacktraceIndex(char *out, intptr_t *buffer, size_t count) {
    for (size_t idx = 2; idx < count; ++idx) {
        intptr_t addr = buffer[idx];
        const char *symbol = "      ";
        const char *dlfile = "      ";

        Dl_info info;
        if (dladdr((void *) addr, &info)) {
            if (info.dli_sname) {
                symbol = info.dli_sname;
            }
            if (info.dli_fname) {
                dlfile = info.dli_fname;
            }
        } else {
            strcat(out, "#                               \n");
            continue;
        }
        char temp[50];
        memset(temp, 0, sizeof(temp));
        sprintf(temp, "%zu", idx);
        strcat(out, "#");
        strcat(out, temp);
        strcat(out, ": ");
        memset(temp, 0, sizeof(temp));
        sprintf(temp, "0x%x", addr);
        strcat(out, temp);
        strcat(out, "  ");
        strcat(out, symbol);
        strcat(out, "      ");
        strcat(out, dlfile);
        strcat(out, "\n");
    }
}

char *backtraceToLogcat(bool iscan) {

    const size_t maxStackDeep = 6;
    intptr_t stackBuf[maxStackDeep];
    char outBuf[2048];
    memset(outBuf, 0, sizeof(outBuf));
    dumpBacktraceIndex(outBuf, stackBuf, captureBacktrace(stackBuf, maxStackDeep));

    if (iscan) {
        LOGI("backtraceToLogcat: %s\n", outBuf);
    }

    //
    return outBuf;
}




jobject     (*oldCallObjectMethodV)(JNIEnv *, jobject, jmethodID, va_list);
jobject myCallObjectMethodV(JNIEnv *env, jobject obj, jmethodID mid, va_list list) {
    jobject oldCallObjectMethod = oldCallObjectMethodV(env, obj, mid, list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]",  MAKE_ARG_ARRAY("CallObjectMethodV", list, (Method *) mid) ,  oldCallObjectMethod);

    }
    return oldCallObjectMethod;
}




jboolean    (*oldCallBooleanMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jboolean    newCallBooleanMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jboolean jbooleanv=oldCallBooleanMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%d]", MAKE_ARG_ARRAY("newCallBooleanMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}


jbyte       (*oldCallByteMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jbyte       myCallByteMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jbyte jbooleanv=oldCallByteMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%d]", MAKE_ARG_ARRAY("myCallByteMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}



jchar       (*oldCallCharMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jchar       myCallCharMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jchar jbooleanv=oldCallCharMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%d]", MAKE_ARG_ARRAY("myCallCharMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}



jshort      (*oldCallShortMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jshort       myCallShortMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jshort jbooleanv=oldCallShortMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%d]", MAKE_ARG_ARRAY("oldCallShortMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}



jint        (*oldCallIntMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jint       myCallIntMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jint jbooleanv=oldCallIntMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%d]", MAKE_ARG_ARRAY("oldCallIntMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}





jlong       (*oldCallLongMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jlong       myCallLongMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jlong jbooleanv=oldCallLongMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%ld]", MAKE_ARG_ARRAY("myCallLongMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}



jfloat      (*oldCallFloatMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jfloat       myCallFloatMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jfloat jbooleanv=oldCallFloatMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%ld]", MAKE_ARG_ARRAY("oldCallFloatMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}




jdouble     (*oldCallDoubleMethodV)(JNIEnv*, jobject, jmethodID, va_list);
jdouble       myCallDoubleMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    jdouble jbooleanv=oldCallDoubleMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%ld]", MAKE_ARG_ARRAY("oldCallDoubleMethodV", list, (Method *) jid), jbooleanv);
    }
    return jbooleanv;
}




void        (*oldCallVoidMethodV)(JNIEnv *, jobject, jmethodID, va_list);
void       myCallVoidMethodV(JNIEnv*env, jobject obj, jmethodID jid, va_list list){
    oldCallVoidMethodV(env,obj,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s", MAKE_ARG_ARRAY("oldCallVoidMethodV", list, (Method *) jid));
    }
}



jobject     (*oldCallNonvirtualObjectMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jobject       myCallNonvirtualObjectMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jobject jobject1=   oldCallNonvirtualObjectMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualObjectMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}




jboolean    (*oldCallNonvirtualBooleanMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jboolean       myCallNonvirtualBooleanMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jboolean jobject1=   oldCallNonvirtualBooleanMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualBooleanMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}


jbyte       (*oldCallNonvirtualByteMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jbyte       myCallNonvirtualByteMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jbyte jobject1=   oldCallNonvirtualByteMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualByteMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jchar       (*oldCallNonvirtualCharMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jchar       myCallNonvirtualCharMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jchar jobject1=   oldCallNonvirtualCharMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualCharMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}


jshort      (*oldCallNonvirtualShortMethodV)(JNIEnv*, jobject, jclass,   jmethodID, va_list);
jshort       myCallNonvirtualShortMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jshort jobject1=   oldCallNonvirtualShortMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualShortMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jint        (*oldCallNonvirtualIntMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jint       myCallNonvirtualIntMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jint jobject1=   oldCallNonvirtualIntMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualIntMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}


jlong       (*oldCallNonvirtualLongMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jlong       myCallNonvirtualLongMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jlong jobject1=   oldCallNonvirtualLongMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualLongMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jfloat      (*oldCallNonvirtualFloatMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jfloat       myCallNonvirtualFloatMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jfloat jobject1=   oldCallNonvirtualFloatMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualFloatMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jdouble     (*oldCallNonvirtualDoubleMethodV)(JNIEnv*, jobject, jclass,  jmethodID, va_list);
jdouble       myCallNonvirtualDoubleMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    jdouble jobject1=   oldCallNonvirtualDoubleMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallNonvirtualDoubleMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}


void        (*oldCallNonvirtualVoidMethodV)(JNIEnv*, jobject, jclass,   jmethodID, va_list);
void       myCallNonvirtualVoidMethodV(JNIEnv*env, jobject obj,jclass jclass1, jmethodID jid, va_list list){
    oldCallNonvirtualVoidMethodV(env,obj,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s", MAKE_ARG_ARRAY("oldCallNonvirtualVoidMethodV", list, (Method *) jid));
    }
}




jobject     (*oldCallStaticObjectMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jobject       myCallStaticObjectMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jobject jobject1=   oldCallStaticObjectMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticObjectMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jboolean    (*oldCallStaticBooleanMethodV)(JNIEnv*, jclass, jmethodID,   va_list);
jboolean       myCallStaticBooleanMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jboolean jobject1=   oldCallStaticBooleanMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticBooleanMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jbyte       (*oldCallStaticByteMethodV)(JNIEnv*, jclass, jmethodID, va_list);


jbyte       myCallStaticByteMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jbyte jobject1=   oldCallStaticByteMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticByteMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jchar       (*oldCallStaticCharMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jchar       myCallStaticCharMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jchar jobject1=   oldCallStaticCharMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticCharMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jshort      (*oldCallStaticShortMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jshort       myCallStaticShortMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jshort jobject1=   oldCallStaticShortMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticShortMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jint        (*oldCallStaticIntMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jint       myCallStaticIntMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jint jobject1=   oldCallStaticIntMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticIntMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}




jlong       (*oldCallStaticLongMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jlong       myCallStaticLongMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jlong jobject1=   oldCallStaticLongMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticLongMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jfloat      (*oldCallStaticFloatMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jfloat       myCallStaticFloatMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jfloat jobject1=   oldCallStaticFloatMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticFloatMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}



jdouble     (*oldCallStaticDoubleMethodV)(JNIEnv*, jclass, jmethodID, va_list);
jdouble       myCallStaticDoubleMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    jdouble jobject1=   oldCallStaticDoubleMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("oldCallStaticDoubleMethodV", list, (Method *) jid),jobject1);
    }
    return jobject1;
}


void        (*oldCallStaticVoidMethodV)(JNIEnv*, jclass, jmethodID, va_list);
void       myCallStaticVoidMethodV(JNIEnv*env,jclass jclass1, jmethodID jid, va_list list){
    oldCallStaticVoidMethodV(env,jclass1,jid,list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s", MAKE_ARG_ARRAY("oldCallStaticVoidMethodV", list, (Method *) jid));
    }
}



void        (*oldSetObjectField)(JNIEnv*, jobject, jfieldID, jobject);
void        mySetObjectField(JNIEnv*env, jobject job1, jfieldID jid, jobject job2){
    oldSetObjectField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s","mySetObjectField", field->clazz->descriptor, field->name, field->signature);
    }
}




void        (*oldSetBooleanField)(JNIEnv*, jobject, jfieldID, jboolean);
void        mySetBooleanField(JNIEnv*env, jobject job1, jfieldID jid, jboolean job2){
    oldSetBooleanField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetBooleanField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}



void        (*oldSetByteField)(JNIEnv*, jobject, jfieldID, jbyte);
void        mySetByteField(JNIEnv*env, jobject job1, jfieldID jid, jbyte job2){
    oldSetByteField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetByteField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetCharField)(JNIEnv*, jobject, jfieldID, jchar);
void        mySetCharField(JNIEnv*env, jobject job1, jfieldID jid, jchar job2){
    oldSetCharField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetCharField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetShortField)(JNIEnv*, jobject, jfieldID, jshort);
void        mySetShortField(JNIEnv*env, jobject job1, jfieldID jid, jshort job2){
    oldSetShortField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetShortField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetIntField)(JNIEnv*, jobject, jfieldID, jint);
void        mySetIntField(JNIEnv*env, jobject job1, jfieldID jid, jint job2){
    oldSetIntField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetIntField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}



void        (*oldSetLongField)(JNIEnv*, jobject, jfieldID, jlong);
void        mySetLongField(JNIEnv*env, jobject job1, jfieldID jid, jlong job2){
    oldSetLongField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetLongField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetFloatField)(JNIEnv*, jobject, jfieldID, jfloat);
void        mySetFloatField(JNIEnv*env, jobject job1, jfieldID jid, jfloat job2){
    oldSetFloatField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetFloatField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}




void        (*oldSetDoubleField)(JNIEnv*, jobject, jfieldID, jdouble);
void        mySetDoubleField(JNIEnv*env, jobject job1, jfieldID jid, jdouble job2){
    oldSetDoubleField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetDoubleField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetStaticObjectField)(JNIEnv*, jclass, jfieldID, jobject);
void        mySetStaticObjectField(JNIEnv*env, jclass job1, jfieldID jid, jobject job2){
    oldSetStaticObjectField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticObjectField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetStaticBooleanField)(JNIEnv*, jclass, jfieldID, jboolean);
void        mySetStaticBooleanField(JNIEnv*env, jclass job1, jfieldID jid, jboolean job2){
    oldSetStaticBooleanField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticBooleanField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetStaticByteField)(JNIEnv*, jclass, jfieldID, jbyte);
void        mySetStaticByteField(JNIEnv*env, jclass job1, jfieldID jid, jbyte job2){
    oldSetStaticByteField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticByteField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetStaticCharField)(JNIEnv*, jclass, jfieldID, jchar);
void        mySetStaticCharField(JNIEnv*env, jclass job1, jfieldID jid, jchar job2){
    oldSetStaticCharField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticCharField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}



void        (*oldSetStaticShortField)(JNIEnv*, jclass, jfieldID, jshort);
void        mySetStaticShortField(JNIEnv*env, jclass job1, jfieldID jid, jshort job2){
    oldSetStaticShortField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticShortField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetStaticIntField)(JNIEnv*, jclass, jfieldID, jint);
void        mySetStaticIntField(JNIEnv*env, jclass job1, jfieldID jid, jint job2){
    oldSetStaticIntField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticIntField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}


void        (*oldSetStaticLongField)(JNIEnv*, jclass, jfieldID, jlong);
void        mySetStaticLongField(JNIEnv*env, jclass job1, jfieldID jid, jlong job2){
    oldSetStaticLongField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticLongField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}



void        (*oldSetStaticFloatField)(JNIEnv*, jclass, jfieldID, jfloat);
void        mySetStaticFloatField(JNIEnv*env, jclass job1, jfieldID jid, jfloat job2){
    oldSetStaticFloatField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticFloatField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}



void        (*oldSetStaticDoubleField)(JNIEnv*, jclass, jfieldID, jdouble);
void        mySetStaticDoubleField(JNIEnv*env, jclass job1, jfieldID jid, jdouble job2){
    oldSetStaticDoubleField(env,job1,jid,job2);
    Field *field=(Field *)(&jid);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("%s %s %s %s %d", "oldSetStaticDoubleField",field->clazz->descriptor, field->name, field->signature,job2);
    }
}








jclass (*old_FindClass)(JNIEnv *, const char *name);

jclass new_FindClass(JNIEnv *env, const char *name) {
    LOGI("FindClass(\"%s\") [%x]", name);


    if(!strcmp(name,"")){
        char *backtraceToLogcat_str = (backtraceToLogcat(true));
    }
    jclass jclass1 = old_FindClass(env, name);;
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("FindClass(\"%s\") [%x]", name, jclass1);
    }

    return jclass1;
}


jmethodID (*oldGetStaticMethodID)(JNIEnv *, jclass,  char *, const char *);

jmethodID myGetStaticMethodID(JNIEnv *env, jclass jclass1,  char *methred_name,
                              const char *methred_sgin) {
    jmethodID jmethodID1 = oldGetStaticMethodID(env, jclass1, methred_name, methred_sgin);;
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        methred_name="waitingForDebu";
        LOGI("GetStaticMethodID(%x,\"%s\")%s  [%x]", jclass1, methred_name, methred_sgin,
             jmethodID1);
    }

    return jmethodID1;
}


jmethodID (*oldGetMethodID)(JNIEnv *, jclass, const char *, const char *);

jmethodID myGetMethodID(JNIEnv *env, jclass jclass1, const char *methred_name, const char *methred_sgin) {
    jmethodID jmethodID1 = oldGetMethodID(env, jclass1, methred_name, methred_sgin);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("GetMethodID(%x,\"%s\")%s  [%x]", jclass1, methred_name, methred_sgin, jmethodID1);
    }

    return jmethodID1;
}


jfieldID (*oldGetFieldID)(JNIEnv *, jclass, const char *, const char *);

jfieldID myGetFieldID(JNIEnv *env, jclass jclass1, const char *file_name, const char *file_sign) {
    jfieldID jfieldID1 = oldGetFieldID(env, jclass1, file_name, file_sign);;
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("GetFieldID:(%x,\"%s\",%s) [%x]", jclass1, file_name, file_sign, jfieldID1);
    }

    return jfieldID1;
}

jfieldID (*oldGetStaticFieldID)(JNIEnv *, jclass, const char *, const char *);

jfieldID
myGetStaticFieldID(JNIEnv *env, jclass jclass1, const char *file_name, const char *file_sign) {
    jfieldID jfieldID1 = oldGetStaticFieldID(env, jclass1, file_name, file_sign);;
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("GetStaticFieldID:(%x,\"%s\",%s) [%x]", jclass1, file_name, file_sign, jfieldID1);
    }

    return jfieldID1;
}


const char *(*oldGetStringUTFChars)(JNIEnv *, jstring, jboolean *);

const char *myGetStringUTFChars(JNIEnv *env, jstring str, jboolean *boolean) {
    const char *GetStringUTFChars = oldGetStringUTFChars(env, str, boolean);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("GetStringUTFChars(%s)[%x]", GetStringUTFChars, GetStringUTFChars);
    }
    return GetStringUTFChars;
}


jstring (*oldNewStringUTF)(JNIEnv *, const char *);

jstring myNewStringUTF(JNIEnv *env, const char *str) {
    jstring GetStringUTFChars = oldNewStringUTF(env, str);

    if(strstr(str,"ok|HL-2ETJ41-BZA1PU|验证成功|欢迎使用活力微商1.0!")||strstr(str,"ShowDialog")){



        get_module_base(getpid(),libJpush);
        char *backtraceToLogcat_str = (backtraceToLogcat(true));
        LOGI("我要暂停了");
        sleep(30);
    }


    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        LOGI("NewStringUTF(%s)[%x]", str, GetStringUTFChars);
    }
    return GetStringUTFChars;
}




jint        (*oldRegisterNatives)(JNIEnv*, jclass, const JNINativeMethod*,  jint);
jint       myRegisterNatives(JNIEnv*env, jclass jclass1, const JNINativeMethod* Methods,  jint num){

    JNINativeMethod *tem;
    tem = (JNINativeMethod *) Methods;

    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {

        for (int i = 0; i < num; ++i) {



            LOGI("oldRegisterNatives(%s %s %x)", Methods->name, Methods->signature, Methods->fnPtr);
            Methods++;
        }



    }

    return oldRegisterNatives(env,jclass1,tem,num);
}






jclass (*oldGetSuperclass)(JNIEnv *, jclass);

jclass myGetSuperclass(JNIEnv *env, jclass jclass1) {
    jclass jclass2 = oldGetSuperclass(env, jclass1);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        ClassObject *mycls1=(ClassObject*)&jclass1;
        ClassObject *mycls2=(ClassObject*)&jclass2;

        LOGI("class1:%s   class2:%s",mycls1->descriptor,mycls2->descriptor);

    }
}


jobject (*oldNewObjectV)(JNIEnv *, jclass, jmethodID, va_list);

jobject myNewObjectV(JNIEnv *env, jclass class1, jmethodID mid, va_list list) {

   /* art::mirror::ArtMethod *artmeth = reinterpret_cast<art::mirror::ArtMethod *>(mid);
    HookInfo *info = (HookInfo *)artmeth->native_method_;*/
    jobject myNewObject = oldNewObjectV(env, class1, mid, list);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, libJpush)) {
        LOGI("%s[%x]", MAKE_ARG_ARRAY("NewObject", list, (Method *) mid), myNewObject);
    }
    return myNewObject;
}




void jnihookStart(JNIEnv *env){
   const struct JNINativeInterface *anInterface = env->functions;
    Cydia::MSHookFunction((void *) anInterface->FindClass, (void *) new_FindClass,
                          (void **) &old_FindClass);

    Cydia::MSHookFunction((void *) anInterface->GetStaticMethodID, (void *) &myGetStaticMethodID,
                          (void **) &oldGetStaticMethodID);

   Cydia::MSHookFunction((void *) anInterface->GetFieldID, (void *) &myGetFieldID,
                          (void **) &oldGetFieldID);
    Cydia::MSHookFunction((void *) anInterface->GetStaticFieldID, (void *) &myGetStaticFieldID,
                          (void **) &oldGetStaticFieldID);
    Cydia::MSHookFunction((void *) anInterface->GetMethodID, (void *) &myGetMethodID,
                          (void **) &oldGetMethodID);
    Cydia::MSHookFunction((void *) anInterface->GetStringUTFChars, (void *) &myGetStringUTFChars,
                          (void **) &oldGetStringUTFChars);
    Cydia::MSHookFunction((void *) anInterface->CallObjectMethodV, (void *) &myCallObjectMethodV,
                          (void **) &oldCallObjectMethodV);

    Cydia::MSHookFunction((void *) anInterface->NewObjectV, (void *) &myNewObjectV,
                          (void **) &oldNewObjectV);


    Cydia::MSHookFunction((void *) anInterface->NewStringUTF, (void *) &myNewStringUTF,
                          (void **) &oldNewStringUTF);

    Cydia::MSHookFunction((void *) anInterface->CallVoidMethodV, (void *) &myCallVoidMethodV,
                          (void **) &oldCallVoidMethodV);


    Cydia::MSHookFunction((void *) anInterface->CallBooleanMethodV, (void *) &newCallBooleanMethodV,
                          (void **) &oldCallBooleanMethodV);


    Cydia::MSHookFunction((void *) anInterface->CallByteMethodV, (void *) &myCallByteMethodV,
                          (void **) &oldCallByteMethodV);


    Cydia::MSHookFunction((void *) anInterface->CallCharMethodV, (void *) &myCallCharMethodV,
                          (void **) &oldCallCharMethodV);

    Cydia::MSHookFunction((void *) anInterface->SetBooleanField, (void *) &mySetBooleanField,
                                                                             (void **) &oldSetBooleanField);

    Cydia::MSHookFunction((void *) anInterface->SetByteField, (void *) &mySetByteField,
                          (void **) &oldSetByteField);

    Cydia::MSHookFunction((void *) anInterface->SetCharField, (void *) &mySetCharField,
                          (void **) &oldSetCharField);

    Cydia::MSHookFunction((void *) anInterface->SetIntField, (void *) &mySetIntField,
                          (void **) &oldSetIntField);

    Cydia::MSHookFunction((void *) anInterface->SetLongField, (void *) &mySetLongField,
                          (void **) &oldSetLongField);



    Cydia::MSHookFunction((void *) anInterface->SetStaticBooleanField, (void *) &mySetStaticBooleanField,
                          (void **) &oldSetStaticBooleanField);

    Cydia::MSHookFunction((void *) anInterface->SetStaticByteField, (void *) &mySetStaticByteField,
                          (void **) &oldSetStaticByteField);

    Cydia::MSHookFunction((void *) anInterface->SetStaticCharField, (void *) &mySetStaticCharField,
                          (void **) &oldSetStaticCharField);

    Cydia::MSHookFunction((void *) anInterface->SetStaticIntField, (void *) &mySetStaticIntField,
                          (void **) &oldSetStaticIntField);

    /*Cydia::MSHookFunction((void *) anInterface->SetStaticLongField, (void *) &mySetStaticLongField,
                          (void **) &oldSetStaticLongField);
*/

    Cydia::MSHookFunction((void *) anInterface->CallNonvirtualObjectMethodV, (void *) &myCallNonvirtualObjectMethodV,
                          (void **) &oldCallNonvirtualObjectMethodV);


    Cydia::MSHookFunction((void *) anInterface->SetStaticDoubleField, (void *) &mySetStaticDoubleField,
                          (void **) &oldSetStaticDoubleField);

    Cydia::MSHookFunction((void *) anInterface->SetDoubleField, (void *) &mySetDoubleField,
                          (void **) &oldSetDoubleField);


    Cydia::MSHookFunction((void *) anInterface->CallShortMethodV, (void *) &myCallShortMethodV,
                          (void **) &oldCallShortMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallIntMethodV, (void *) &myCallIntMethodV,
                          (void **) &oldCallIntMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallLongMethodV, (void *) &myCallLongMethodV,
                          (void **) &oldCallLongMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallFloatMethodV, (void *) &myCallFloatMethodV,
                          (void **) &oldCallFloatMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallDoubleMethodV, (void *) &myCallDoubleMethodV,
                          (void **) &oldCallDoubleMethodV);

    Cydia::MSHookFunction((void *) anInterface->SetStaticFloatField, (void *) &mySetStaticFloatField,
                          (void **) &oldSetStaticFloatField);

    Cydia::MSHookFunction((void *) anInterface->SetStaticShortField, (void *) &mySetStaticShortField,
                          (void **) &oldSetStaticShortField);


    Cydia::MSHookFunction((void *) anInterface->SetStaticObjectField, (void *) &mySetStaticObjectField,
                          (void **) &oldSetStaticObjectField);

    Cydia::MSHookFunction((void *) anInterface->SetFloatField, (void *) &mySetFloatField,
                          (void **) &oldSetFloatField);

    Cydia::MSHookFunction((void *) anInterface->SetShortField, (void *) &mySetShortField,
                          (void **) &oldSetShortField);

    Cydia::MSHookFunction((void *) anInterface->SetObjectField, (void *) &mySetObjectField,
                          (void **) &oldSetObjectField);

    Cydia::MSHookFunction((void *) anInterface->CallStaticVoidMethodV, (void *) &myCallStaticVoidMethodV,
                          (void **) &oldCallStaticVoidMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticDoubleMethodV, (void *) &myCallStaticDoubleMethodV,
                          (void **) &oldCallStaticDoubleMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticFloatMethodV, (void *) &myCallStaticFloatMethodV,
                          (void **) &oldCallStaticFloatMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticLongMethodV, (void *) &myCallStaticLongMethodV,
                          (void **) &oldCallStaticLongMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticObjectMethodV, (void *) &myCallStaticObjectMethodV,
                          (void **) &oldCallStaticObjectMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticBooleanMethodV, (void *) &myCallStaticBooleanMethodV,
                          (void **) &oldCallStaticBooleanMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticByteMethodV, (void *) &myCallStaticByteMethodV,
                          (void **) &oldCallStaticByteMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticCharMethodV, (void *) &myCallStaticCharMethodV,
                          (void **) &oldCallStaticCharMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticShortMethodV, (void *) &myCallStaticShortMethodV,
                          (void **) &oldCallStaticShortMethodV);

    Cydia::MSHookFunction((void *) anInterface->CallStaticIntMethodV, (void *) &myCallStaticIntMethodV,
                          (void **) &oldCallStaticIntMethodV);

    Cydia::MSHookFunction((void *) anInterface->RegisterNatives, (void *) &myRegisterNatives,
                          (void **) &oldRegisterNatives);

}



#endif //HOOKTEST_JNIHOOK_H
