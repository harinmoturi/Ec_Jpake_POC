//
// Created by Eli Harris on 2019-10-30.
//
# define FIX_TEST_VALUES 0


#include <stdlib.h>
#include "ec-jpake.h"
#include "sample.h"

#include <android/log.h>


struct __attribute__((packed)) {
    uint8_t opcode;
    uint8_t curve;
    uint8_t  signerID[MAX_SIGNER_SIZE];
} client_hello;


// Define the buffer that is going to hold the information
//_dbuffer buff;
ecjpake_buffer_t new_buff;


char *writeRoundOneJ(size_t *len, int Round_number) {


#if FIX_TEST_VALUES
    uint32_t p1[MAX_KEY_SIZE], p2[MAX_KEY_SIZE];
    uECC_vli_bytesToNative(p1, ecjpake_test_x1, 32);
    uECC_vli_bytesToNative(p2, ecjpake_test_x1, 32);
    writeRoundOneWith(p1, p2, &buff);
#else
    writeRoundOne_Two(&new_buff, Round_number);
#endif


    void *data;

    if ((Round_number == 1) ||(Round_number == 5)) {
        *len = new_buff.round1.size; //buff.round1.size; //A/ + 2;
        data = malloc(new_buff.round1.size);
        memcpy(data, new_buff.round1.buffer, new_buff.round1.size);}
     else if (Round_number == 2) {
        *len = new_buff.round2.size; //buff.round1.size; //A/ + 2;
        data = malloc(new_buff.round2.size); //A/+ 2);
        memcpy(data, new_buff.round2.buffer, new_buff.round2.size);}


    return (char *) data;

}

char* writeRoundTwoJ(size_t *len) {

   writeRoundTwo(&new_buff);

    // Set the length
    *len = new_buff.round3.size;

    // We are going to write the data into this
    void *data = malloc(new_buff.round3.size);


    memcpy(data, new_buff.round3.buffer, new_buff.round3.size);

    // Now we are going to cast the data
    return (char *) data;

}

char *getKey(size_t *len) {

    *len = 16;

    uint8_t key[32], in[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    uECC_vli_nativeToBytes(in, curve->num_bytes, (uint32_t *) & new_buff.round3.key);
    memset(in + curve->num_bytes, 0, 32 - curve->num_bytes);
    sha256_update(&ctx, in, 32);
    sha256_final(&ctx, key);

    // We are going to write the data into this
    void *data = malloc(16);
    memcpy(data, key, 16);

    // Now we are going to cast the data
    return (char *) data;

}

int readRoundOneJ(const signed char *round, size_t sz, int Round_number) {

    printf("readRoundOneJ\n");


    if(Round_number == 1) {
        new_buff.round1.size = sz;
        memcpy(new_buff.round1.buffer, round,sz);
    }
    else if((Round_number == 2)||(Round_number == 5)){
        new_buff.round2.size = sz;
        memcpy(new_buff.round2.buffer, round,sz);
    }


    int err = readRoundOne(&new_buff, Round_number);

    printf("err = %d\n", err);

    if (!err) {
        printf("Checked!\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Checked!");//Or ANDROID_LOG_INFO, ...

    } else if (err == -1) {
        printf("Size error.\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", "Size Error");//Or ANDROID_LOG_INFO, ...

    } else if (err == -2) {
        printf("Size error.\n");

        __android_log_write(ANDROID_LOG_ERROR, "Tag", " not be verified");//Or ANDROID_LOG_INFO, ...

    }

    return err;
}


void readRoundTwoJ(const signed char *round, size_t sz) {

    printf("readRoundTwoJ\n");

    new_buff.round3.size = sz;
    memcpy(new_buff.round3.buffer, round,sz);

    int err = readRoundThree(&new_buff);

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


    //A/ temp challenge
    uint8_t temp_challenge[] =  {0,1, 2, 3,4,5,6,7,8,9,10,11,12,13,14,15};

    //A/strcpy(client_hello.signerID, "OurSignerID");
    memcpy(client_hello.signerID,  temp_challenge, 16);

    client_hello.curve = secp256r1;

    memcpy(data, &client_hello, sizeof(client_hello));

    return data;

}


void setInfo(const signed char *round, size_t sz) {

    //memcpy(&client_hello, (void *) round, sz);

    setSigns("device","transmitter");

}

void init() {

    int err = 0;
    err = ECjpakeSetup(secp256r1, ECJPAKE_CLIENT, ecjpake_test_password, sizeof(ecjpake_test_password));

    if (err == -1) {
        printf("This curve is not supported.\n");
    }

    //char _mySign[] = "OurSignerID";
    //char _recSign[] = "OurSignerID";

    char _mySign[] = "device";
    char _recSign[] = "transmitter";

    setSigns(_mySign, _recSign);

}

