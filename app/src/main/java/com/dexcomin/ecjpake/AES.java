package com.dexcomin.ecjpake;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void setKey(byte[] key) {
        secretKey = new SecretKeySpec(key, "AES");

    }

    public static byte[] encrypt(byte[] encrypt, byte[] key) {
        try {
            setKey(key);
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(encrypt);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

//    public static String decrypt(String strToDecrypt, String secret) {
//        try {
//            setKey(secret);
//            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
//            cipher.init(Cipher.DECRYPT_MODE, secretKey);
//            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
//        } catch (Exception e) {
//            System.out.println("Error while decrypting: " + e.toString());
//        }
//        return null;
//    }
}