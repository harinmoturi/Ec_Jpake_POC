#include "../../../../../../Library/Android/sdk/ndk-bundle/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/include/stdint.h"

%module ecjpake
%include "cpointer.i"
%include various.i

%typemap(jni)  char * "jbyteArray"
%typemap(jtype)  char * "byte[]"
%typemap(jstype)  char * "byte[]"
%typemap(javaout) char * {
        return $jnicall;
}

%typemap(in,numinputs=0,noblock=1) size_t *len {
        size_t length=0;
        $1 = &length;
}

%typemap(out) char * {
        $result = JCALL1(NewByteArray, jenv, length);
        JCALL4(SetByteArrayRegion, jenv, $result, 0, length, $1);
}


%typemap(jtype) (const signed char *round, size_t sz) "byte[]"
%typemap(jstype) (const signed char *round, size_t sz) "byte[]"
%typemap(jni) (const signed char *round, size_t sz) "jbyteArray"
%typemap(javain) (const signed char *round, size_t sz) "$javainput"

%typemap(in,numinputs=1) (const signed char *round, size_t sz) {
$1 = JCALL2(GetByteArrayElements, jenv, $input, NULL);
$2 = JCALL1(GetArrayLength, jenv, $input);
}

%typemap(freearg) (const signed char *round, size_t sz) {
    // Or use  0 instead of ABORT to keep changes if it was a copy
    JCALL3(ReleaseByteArrayElements, jenv, $input, $1, JNI_ABORT);
}

%inline %{

#include "ec-jpake.h"

extern char * writeRoundOneJ(size_t * len, int Round_number);

extern char * writeRoundTwoJ(size_t * len);

extern char * getKey(size_t *len);

extern int readRoundOneJ(const signed char * round, size_t sz, int Round_number);

extern void readRoundTwoJ(const signed char * round, size_t sz);

extern void setInfo(const signed char * round, size_t sz);

extern char *sayHello(size_t *len);

extern void init();

%}

