//
// Created by Eli Harris on 2019-10-30.
//
# define FIX_TEST_VALUES 1


#include "ec-jpake.h"
#include <stdlib.h>
#include "sample.h"

#include <android/log.h>


struct __attribute__((packed)) {
    uint8_t opcode;
    uint8_t curve;
    char signerID[MAX_SIGNER_SIZE];
} client_hello;


// Define the buffer that is going to hold the information
_dbuffer buff;

char *writeRoundOneJ(size_t *len) {


#if FIX_TEST_VALUES
    uint32_t p1[MAX_KEY_SIZE], p2[MAX_KEY_SIZE];
    uECC_vli_bytesToNative(p1, ecjpake_test_x3, 32);
    uECC_vli_bytesToNative(p2, ecjpake_test_x4, 32);
    writeRoundOneWith(p1, p2, &buff);
#else
    writeRoundOne(&buff);
#endif

    // Set the length
    *len = buff.round1.size + 2;

    // We are going to write the data into this
    void *data = malloc(buff.round1.size + 2);

    void *sizePointer = (void *) &buff.round1.size;

    // Now we are going to copy over the memory
    memcpy(data, (sizePointer + 1), 1);
    memcpy(data + 1, (sizePointer + 0), 1);

    // Now we are going to copy over the buffer into the pointer
    memcpy(data + 2, buff.round1.buffer, buff.round1.size);

    // Now we are going to cast the data
    return (char *) data;

}

char *writeRoundTwoJ(size_t *len) {


    writeRoundOne(&buff);

    // Set the length
    *len = buff.round2.size + 2;

    // We are going to write the data into this
    void *data = malloc(buff.round2.size + 2);

    void *sizePointer = (void *) &buff.round2.size;

    // Now we are going to copy over the memory
    memcpy(data, (sizePointer + 1), 1);
    memcpy(data + 1, (sizePointer + 0), 1);

    // Now we are going to copy over the buffer into the pointer
    memcpy(data + 2, buff.round2.buffer, buff.round2.size);

    // Now we are going to cast the data
    return (char *) data;

}

char *getKey(size_t *len) {

    *len = 16;

    uint8_t key[32], in[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    uECC_vli_nativeToBytes(in, curve->num_bytes, (uint32_t *) & buff.round2.key);
    memset(in + curve->num_bytes, 0, 32 - curve->num_bytes);
    sha256_update(&ctx, in, 32);
    sha256_final(&ctx, key);

    // We are going to write the data into this
    void *data = malloc(16);
    memcpy(data, key, 16);

    // Now we are going to cast the data
    return (char *) data;

}

void readRoundOneJ(const signed char *round, size_t sz) {

    buff.round1.size = 0;

    uint16_t size = 0;

    void *sizePointer = (void *) &buff.round1.size;

    memcpy(sizePointer, round + 1, 1);
    memcpy(sizePointer + 1, round, 1);
    memcpy(buff.round1.buffer, round + 2, buff.round1.size);

    int err = readRoundOne(&buff);

    if (!err) {
        printf("Checked!\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Checked!");//Or ANDROID_LOG_INFO, ...

    } else if (err == -1) {
        printf("Size error.\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Size Error");//Or ANDROID_LOG_INFO, ...

    } else if (err == -2) {
        printf("Size error.\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Could not be verified");//Or ANDROID_LOG_INFO, ...

    }

}


void readRoundTwoJ(const signed char *round, size_t sz) {

    buff.round2.size = 0;

    uint16_t size = 0;

    void *sizePointer = (void *) &buff.round2.size;

    memcpy(sizePointer, round + 1, 1);
    memcpy(sizePointer + 1, round, 1);
    memcpy(buff.round2.buffer, round + 2, buff.round2.size);

    int err = readRoundTwo(&buff);

    if (!err) {
        printf("Checked!\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Checked!");//Or ANDROID_LOG_INFO, ...

    } else if (err == -1) {
        printf("Size error.\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Size Error");//Or ANDROID_LOG_INFO, ...

    } else if (err == -2) {
        printf("Size error.\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Could not be verified");//Or ANDROID_LOG_INFO, ...

    }

}


char *sayHello(size_t *len) {


    *len = sizeof(client_hello);

    // We are going to write the data into this
    void *data = malloc(sizeof(client_hello));

    client_hello.opcode = 0x0A;
    strcpy(client_hello.signerID, "OurSignerID");
    client_hello.curve = secp256r1;

    memcpy(data, &client_hello, sizeof(client_hello));

    return data;

}


void setInfo(const signed char *round, size_t sz) {

    memcpy(&client_hello, (void *) round, sz);

    setSigns("OurSignerID", "OurSignerID");

}

void init() {

    int err = 0;
    err = ECjpakeSetup(secp256r1, ECJPAKE_SERVER, ecjpake_test_password, sizeof(ecjpake_test_password));

    if (err == -1) {
        printf("This curve is not supported.\n");
    }

    char _mySign[] = "OurSignerID";
    char _recSign[] = "OurSignerID";

    setSigns("OurSignerID", "OurSignerID");

}

