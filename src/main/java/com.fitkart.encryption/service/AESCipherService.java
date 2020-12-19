package com.fitkart.encryption.service;

import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class AESCipherService {

    private static final int IV_SIZE = 96;
    private static final int TAG_BIT_LENGTH = 128;
    private static String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding";
    private static final String DELIMITER = "alias:";

    // Encryption Strategy #1
    public String encryptMessage(String message, SecretKey aesKey, byte[] aadData) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        GCMParameterSpec gcmParameterSpec = generateGCMParameterSpec();
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec, new SecureRandom());
        cipher.updateAAD(aadData);

        byte[] cipherTextInByteArr = cipher.doFinal(message.getBytes());

        byte[] iv = gcmParameterSpec.getIV();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + cipherTextInByteArr.length);
        byteBuffer.put((byte) iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherTextInByteArr);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    // Encryption Strategy #2
    public String encryptMessageWithAlias(String message, SecretKey aesKey, byte[] aadData, String aliasName) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        GCMParameterSpec gcmParameterSpec = generateGCMParameterSpec();
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec, new SecureRandom());
        cipher.updateAAD(aadData);

        byte[] cipherTextInByteArr = cipher.doFinal(message.getBytes());

        byte[] iv = gcmParameterSpec.getIV();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + cipherTextInByteArr.length);
        byteBuffer.put((byte) iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherTextInByteArr);

        return Base64.getEncoder().encodeToString(byteBuffer.array())+DELIMITER+aliasName;
    }

    // Decryption Strategy #1 & #2
    public String decryptCipher(String cipherText, SecretKey aesKey, byte[] aadData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] encryptedMessage = Base64.getDecoder().decode(cipherText);

        int initialOffset = 1;
        int ivLength = encryptedMessage[0];

        if (ivLength != 96) {
            throw new IllegalStateException("Unexpected iv length");
        }

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, generateGCMParameterSpec(encryptedMessage), new SecureRandom());
        cipher.updateAAD(aadData);

        byte[] plainTextInByteArr = cipher.doFinal(encryptedMessage, initialOffset + ivLength, encryptedMessage.length - (initialOffset + ivLength));

        return new String(plainTextInByteArr);
    }

    // Encryption Strategy #3
    public String encryptMessageWithAliasActive(String message, SecretKey aesKey, byte[] aadData, String aliasName) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        GCMParameterSpec gcmParameterSpec = generateGCMParameterSpec();
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec, new SecureRandom());
        cipher.updateAAD(aadData);

        byte[] cipherTextInByteArr = cipher.doFinal(message.getBytes());

        byte[] iv = gcmParameterSpec.getIV();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + cipherTextInByteArr.length);
        byteBuffer.put((byte) iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherTextInByteArr);

        return Base64.getEncoder().encodeToString(byteBuffer.array())+DELIMITER+aliasName;
    }

    // Decryption Strategy #3
    public String decryptCipherWithAlias(String cipherText, SecretKey aesKey, byte[] aadData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] encryptedMessage = Base64.getDecoder().decode(cipherText);

        int initialOffset = 1;
        int ivLength = encryptedMessage[0];

        if (ivLength != 96) {
            throw new IllegalStateException("Unexpected iv length");
        }

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, generateGCMParameterSpec(encryptedMessage), new SecureRandom());
        cipher.updateAAD(aadData);

        byte[] plainTextInByteArr = cipher.doFinal(encryptedMessage, initialOffset + ivLength, encryptedMessage.length - (initialOffset + ivLength));

        return new String(plainTextInByteArr);
    }


    private GCMParameterSpec generateGCMParameterSpec() {

        // Generating IV
        byte iv[] = new byte[IV_SIZE];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

        // Initialize GCM Parameters
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

        secRandom.nextBytes(iv);

        return gcmParamSpec;
    }

    private GCMParameterSpec generateGCMParameterSpec(byte[] encryptedMessage) {

        int initialOffset = 1;
        int ivLength = encryptedMessage[0];

        if (ivLength != 96) {
            throw new IllegalStateException("Unexpected iv length");
        }
        // Initialize GCM Parameters
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, encryptedMessage, initialOffset, ivLength);

        return gcmParamSpec;
    }
}