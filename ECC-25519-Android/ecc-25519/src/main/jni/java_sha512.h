#ifndef _INCLUDED_JAVA_SHA512
#define _INCLUDED_JAVA_SHA512
#include <stddef.h>
#include <jni.h>

typedef struct {
	jobject obj;
	jclass cls;
	jmethodID SHA512_Init_ID;
	jmethodID SHA512_Update_ID;
	jmethodID SHA512_Final_ID;
} SHA512_CTX;

void SHA512_Init(SHA512_CTX *ctx);
void SHA512_Update(SHA512_CTX *ctx, const unsigned char* message, size_t message_len);
void SHA512_Final(unsigned char* hash, SHA512_CTX *ctx);
void SHA512(const unsigned char* m, size_t n, unsigned char* md);

#endif