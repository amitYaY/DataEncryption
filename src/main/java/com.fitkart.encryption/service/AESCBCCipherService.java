package com.fitkart.encryption.service;

import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class AESCBCCipherService {

    private static final int IV_SIZE = 16;
    private static String ALGO_TRANSFORMATION_STRING = "AES/CBC/PKCS5Padding";

    public String encryptMessage(String message, SecretKey aesKey) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        IvParameterSpec ivParameterSpec = generateIVParameterSpec();
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);

        byte[] cipherTextInByteArr = cipher.doFinal(message.getBytes());

        byte[] iv = ivParameterSpec.getIV();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + cipherTextInByteArr.length);
        byteBuffer.put((byte) iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherTextInByteArr);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }


    public String decryptCipher(String cipherText, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] encryptedMessage = Base64.getDecoder().decode(cipherText);

        int initialOffset = 1;
        int ivLength = encryptedMessage[0];

        if (ivLength != 16) {
            throw new IllegalStateException("Unexpected iv length");
        }

        Cipher cipher = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, generateIVParameterSpec(encryptedMessage));

        byte[] plainTextInByteArr = cipher.doFinal(encryptedMessage, initialOffset + ivLength, encryptedMessage.length - (initialOffset + ivLength));

        return new String(plainTextInByteArr);
    }


    private IvParameterSpec generateIVParameterSpec() {

        // Generating IV
        byte iv[] = new byte[IV_SIZE];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

        // Initialize GCM Parameters
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        secRandom.nextBytes(iv);

        return ivspec;
    }

    private IvParameterSpec generateIVParameterSpec(byte[] encryptedMessage) {

        int initialOffset = 1;
        int ivLength = encryptedMessage[0];

        if (ivLength != 16) {
            throw new IllegalStateException("Unexpected iv length");
        }
        // Initialize GCM Parameters
        IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptedMessage, initialOffset, ivLength);

        return ivParameterSpec;
    }
}
