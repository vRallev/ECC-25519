#include "com_github_dazoe_android_Ed25519.h"
#include "ed25519.h"

JNIEXPORT jbyteArray JNICALL Java_com_github_dazoe_android_Ed25519_ExpandPrivateKeyN(JNIEnv *env, jclass cls, jbyteArray seed) {
	_env = env;
	unsigned char* seedData = (unsigned char*)(*env)->GetByteArrayElements(env, seed, NULL);
	unsigned char pk[32];
	unsigned char sk[64];
	int i;
	for (i = 0; i < 32; i++) {
		sk[i] = seedData[i];
	}
	(*env)->ReleaseByteArrayElements(env, seed, (jbyte*)seedData, JNI_ABORT);
	crypto_sign_keypair(pk, sk);
	jbyteArray result = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, result, 0, 64, (jbyte*)sk);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_github_dazoe_android_Ed25519_SignN(JNIEnv *env, jclass cls, jbyteArray message, jbyteArray privateKey) {
	_env = env;
	unsigned long long messageLen = (*env)->GetArrayLength(env, message);
	unsigned char* messageData = (unsigned char*)(*env)->GetByteArrayElements(env, message, NULL);
	unsigned char* privateKeyData = (unsigned char*)(*env)->GetByteArrayElements(env, privateKey, NULL);
	unsigned long long signatureMessageLen = 64 + messageLen;
	unsigned char signatureMessageData[signatureMessageLen];
	crypto_sign(signatureMessageData, &signatureMessageLen, messageData, messageLen, privateKeyData);
	(*env)->ReleaseByteArrayElements(env, message, (jbyte*)messageData, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, privateKey, (jbyte*)privateKeyData, JNI_ABORT);
	jbyteArray signature = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, signature, 0, 64, (jbyte*)signatureMessageData);
	return signature;
}

JNIEXPORT jint JNICALL Java_com_github_dazoe_android_Ed25519_VerifyN(JNIEnv *env, jclass cls, jbyteArray message, jbyteArray signature, jbyteArray publicKey) {
	_env = env;
	size_t messageLen = (*env)->GetArrayLength(env, message);
	unsigned char* signatureData = (unsigned char*)(*env)->GetByteArrayElements(env, signature, NULL);
	unsigned char* messageData = (unsigned char*)(*env)->GetByteArrayElements(env, message, NULL);
	unsigned char* publicKeyData = (unsigned char*)(*env)->GetByteArrayElements(env, publicKey, NULL);
	int result = crypto_sign_verify(signatureData, messageData, messageLen, publicKeyData);
	(*env)->ReleaseByteArrayElements(env, signature, (jbyte*)signatureData, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, message, (jbyte*)messageData, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, publicKey, (jbyte*)publicKeyData, JNI_ABORT);
	return result;
}
