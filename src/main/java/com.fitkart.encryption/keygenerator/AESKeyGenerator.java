package com.fitkart.encryption.keygenerator;

import com.fitkart.encryption.keystore.KeyStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Properties;

@Component
public class AESKeyGenerator {

    @Autowired
    private KeyStoreService keyStoreService;

    private static final int AES_KEY_SIZE = 256;

    public String generateAESKeyWithTimestampSuffixAlias() {

        Properties secretKeyFile = null;
        try {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            SecretKey aesKey = keygen.generateKey();
            secretKeyFile = keyStoreService.storeNewActiveKeyInPropertyFile(LocalDateTime.now(), aesKey);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        assert secretKeyFile != null;

        return secretKeyFile.toString();
    }

    public String rotateKeyInKeyStoreWithTimestampSuffix() {

        Properties secretKeyFile = null;

        try {
            // Generating Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES"); // Key Will be used for AES
            keygen.init(AES_KEY_SIZE);
            SecretKey aesKey = keygen.generateKey();
            secretKeyFile = keyStoreService.rotateKeyInKeyPropertyFile(LocalDateTime.now(), aesKey);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        assert secretKeyFile != null;

        return  secretKeyFile.toString();
    }
}
