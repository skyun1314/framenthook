

#include "jnihook.h"
#include "sokect_hook.h"
#include "hook_device.h"





void* (*old_jiemistr)(void *ssl, char *buf, int len);

void* new_jiemistr(void *ssl, char *buf, int len) {
    LOGI("解密：%s",buf);
    return old_jiemistr(ssl,buf,len);
}


void haha1(JNIEnv *env, jobject instance, jint cookie, jstring pac){}
void haha2(JNIEnv *env, jobject instance){}
static JNINativeMethod method[] = {

        {"JNIverify1",
                "(ILjava/lang/String;)V",
                (void *) haha1
        },
        {"JNIverify2",
                    "()V",
                    (void *) haha2
        }

};


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {



    JNIEnv *env = NULL;
    jint result = -1;


    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return result;
    }
    LOGI("执行我自己的so：%d", getpid());




    Cydia::MSHookFunction("libpolicy_lib.so",  "SSL_write",  (void *) new_jiemistr,
                          (void **) &old_jiemistr);


  //  jnihookStart(env);
   // hook_send_recv_fopen();
   /* jclass jclass1 = env->FindClass("android/app/ActivityThread/AppBindData");
    int ret = env->RegisterNatives(jclass1, method, 2);

    if (ret < 0) {
        return result;
    }*/


/*  void* libwechatnonmsg= dlopen("/data/local/libwechatnonmsg.so",RTLD_LAZY);

    if(libwechatnonmsg){
        LOGI("装载libwechatnonmsg成功:%x",libwechatnonmsg);
    }else{
        LOGI("装载libwechatnonmsg失败");
    }*/

  /* void* libwechatnonmsg= get_module_base(getpid(),"libwechatnonmsg.so");
    LOGI("查找完毕libwechatnonmsg");
    LOGI("libwechatnonmsg:%x",libwechatnonmsg);


    if(libwechatnonmsg){
     long  xx= ((long)libwechatnonmsg+0x0004EAA8+1);
        LOGI("准备hook这个地址：%x",xx);
        Cydia::MSHookFunction(  (void*)xx, (  void *) &mysub_4EAA8, (void **) &oldsub_4EAA8);
    }else{
        LOGI("地址没有找到。hook失败");
    }*/


  /*
    hook_send_recv_fopen();
    hook_device();*/
 /*  jclass  AppBindData=env->FindClass("android/app/ActivityThread/AppBindData");
    jmethodID init =env->GetMethodID(AppBindData,"<init>","()V");
  jmethodID seta= env->GetMethodID(AppBindData,"seta","(ZLjava/lang/String;I)Landroid/app/ActivityThread/AppBindData;");

 jobject myAppBindData=   env->NewObject(AppBindData,init);
 jobject  retur=  env->CallObjectMethod(myAppBindData,seta,1,env->NewStringUTF("haha"),5);
*/
    result = JNI_VERSION_1_6;

    return result;
}