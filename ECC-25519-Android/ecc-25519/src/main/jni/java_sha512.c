#include "java_sha512.h"
#include "com_github_dazoe_android_Ed25519.h"

void SHA512_Init(SHA512_CTX *ctx) {
	if (_env) {
		ctx->cls = (*_env)->FindClass(_env, "com/github/dazoe/android/Ed25519");
		ctx->SHA512_Init_ID = (*_env)->GetStaticMethodID(_env, ctx->cls, "SHA512_Init", "()Ljava/security/MessageDigest;");
		if (ctx->SHA512_Init_ID == 0) return;
		ctx->SHA512_Update_ID = (*_env)->GetStaticMethodID(_env, ctx->cls, "SHA512_Update", "(Ljava/security/MessageDigest;[B)V");
		if (ctx->SHA512_Update_ID == 0) return;
		ctx->SHA512_Final_ID = (*_env)->GetStaticMethodID(_env, ctx->cls, "SHA512_Final", "(Ljava/security/MessageDigest;)[B");
		if (ctx->SHA512_Final_ID == 0) return;

		ctx->obj = (jobject)(*_env)->CallStaticObjectMethod(_env, ctx->cls, ctx->SHA512_Init_ID);
	}
}

void SHA512_Update(SHA512_CTX *ctx, const unsigned char* message, size_t message_len) {
	if ((_env) && (ctx->obj)) {
		jbyteArray data = (*_env)->NewByteArray(_env, message_len);
		(*_env)->SetByteArrayRegion(_env, data, 0, message_len, (jbyte*)message);
		(*_env)->CallStaticVoidMethod(_env, ctx->cls, ctx->SHA512_Update_ID, ctx->obj, data);
		(*_env)->DeleteLocalRef(_env, data);
	}
}

void SHA512_Final(unsigned char* hash, SHA512_CTX *ctx) {
	if ((_env) && (ctx->obj)) {
		jbyteArray result = (jbyteArray)(*_env)->CallStaticObjectMethod(_env, ctx->cls, ctx->SHA512_Final_ID, ctx->obj);
		int resultLen = (*_env)->GetArrayLength(_env, result);
		unsigned char* resultData = (unsigned char*)(*_env)->GetByteArrayElements(_env, result, NULL);
		int i;
		for (i = 0; i < resultLen; i++) {
			hash[i] = resultData[i];
		}
		(*_env)->ReleaseByteArrayElements(_env, result, (jbyte*)resultData, JNI_ABORT);
		(*_env)->DeleteLocalRef(_env, result);
	}
}

void SHA512(const unsigned char* m, size_t n, unsigned char* md) {
	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, m, n);
	SHA512_Final(md, &ctx);
}

