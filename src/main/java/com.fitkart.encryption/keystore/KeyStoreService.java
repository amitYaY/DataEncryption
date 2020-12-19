package com.fitkart.encryption.keystore;

import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;

import javax.crypto.SecretKey;
import java.io.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Component
public class KeyStoreService {

    private static final String KEY_STORE_PATH = "/Users/a0u007a/Desktop/MyProjects/";

    private static final String ACTIVE_KEY_ALIAS = "activeKey";

    private static final String BACKUP_KEY_ALIAS = "backupKey";

    private static final String ACTIVE_KEY_TIMESTAMP_ALIAS = "activeKeyTimestamp";

    private static final String BACKUP_KEY_TIMESTAMP_ALIAS = "backupKeyTimestamp";

    public Properties storeNewActiveKeyInPropertyFile(LocalDateTime generatedTime, SecretKey aesKey) {

        Properties secretKeyFile = new Properties();
        // Create new property file : secretkeys.properties
        try (FileWriter keyStoreWriter = new FileWriter(KEY_STORE_PATH + "secretkeys.properties")) {

            // Added generated key and generation time in property file
            secretKeyFile.setProperty(ACTIVE_KEY_ALIAS, getKeyStringForSecretKey(aesKey));
            secretKeyFile.setProperty(ACTIVE_KEY_TIMESTAMP_ALIAS, String.valueOf(generatedTime.toEpochSecond(ZoneOffset.UTC)));

            secretKeyFile.store(keyStoreWriter, "Amit Upadhyay");
        } catch (Exception ex) {
            return null;
        }

        return secretKeyFile;
    }

    public Properties rotateKeyInKeyPropertyFile(LocalDateTime generatedTime, SecretKey aesKey) {

        Properties oldSecretKeyFile = new Properties();
        Properties secretKeyFile = new Properties();

        // Get expired SecretKey property file : secretkeys.properties
        try (FileReader keyStoreReader = new FileReader(KEY_STORE_PATH + "secretkeys.properties")) {

            // Added generated key and generation time in property file
            oldSecretKeyFile.load(keyStoreReader);

        } catch (Exception ex) {
            return oldSecretKeyFile;
        }

        // Get Active Key and Active Key Timestamp
        String expiredActiveKey = oldSecretKeyFile.getProperty(ACTIVE_KEY_ALIAS);
        String expiredActiveKeyTimestamp = oldSecretKeyFile.getProperty(ACTIVE_KEY_TIMESTAMP_ALIAS);

        // Create new SecretKey property file : secretkeys.properties
        try (FileWriter keyStoreWriter = new FileWriter(KEY_STORE_PATH + "secretkeys.properties")) {

            // Set Backup Key and Backup Key Timestamp
            secretKeyFile.setProperty(BACKUP_KEY_ALIAS, expiredActiveKey);
            secretKeyFile.setProperty(BACKUP_KEY_TIMESTAMP_ALIAS, expiredActiveKeyTimestamp);

            // Set new Active Key and new Active Key Timestamp
            secretKeyFile.setProperty(ACTIVE_KEY_ALIAS, getKeyStringForSecretKey(aesKey));
            secretKeyFile.setProperty(ACTIVE_KEY_TIMESTAMP_ALIAS, String.valueOf(generatedTime.toEpochSecond(ZoneOffset.UTC)));

            secretKeyFile.store(keyStoreWriter, "New User");

        } catch (Exception ex) {
            return oldSecretKeyFile;
        }

        return secretKeyFile;
    }

    public Map<String, SecretKey> getSecretKeyForEncryption() {

        Map<String, SecretKey> encryptionKeySet = new HashMap<>();
        Properties secretKeyFile = new Properties();

        // Get SecretKey property file : secretkeys.properties
        try (FileReader keyStoreReader = new FileReader(KEY_STORE_PATH + "secretkeys.properties")) {
            secretKeyFile.load(keyStoreReader);
        } catch (Exception ex) {
            return encryptionKeySet;
        }

        // Get Active Key and Active Key Timestamp
        String activeKey = secretKeyFile.getProperty(ACTIVE_KEY_ALIAS);
        String activeKeyTimestamp = secretKeyFile.getProperty(ACTIVE_KEY_TIMESTAMP_ALIAS);

        // Generate SecretKey form Active Key
        SecretKey secretKey = null;
        try {
            secretKey = generateSecretKeyFromKeyString(activeKey);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        encryptionKeySet.put(activeKeyTimestamp, secretKey);

        return encryptionKeySet;
    }

    public SecretKey getSecretKeyForDecryption(final String decryptionKeyAliasPostfix) {

        Properties secretKeyFile = new Properties();

        String decryptionKey = ACTIVE_KEY_ALIAS;
        // Get SecretKey property file : secretkeys.properties
        try (FileReader keyStoreReader = new FileReader(KEY_STORE_PATH + "secretkeys.properties")) {
            secretKeyFile.load(keyStoreReader);
        } catch (Exception ex) {
            return null;
        }

        // Get Active Key and Active Key Timestamp
        String activeKeyTimestamp = secretKeyFile.getProperty(ACTIVE_KEY_TIMESTAMP_ALIAS);
        String backupKeyTimestamp = secretKeyFile.getProperty(BACKUP_KEY_TIMESTAMP_ALIAS);

        // Use decryptionKeyAliasPostfix to determine the Key
        if (!decryptionKeyAliasPostfix.equals(activeKeyTimestamp) && decryptionKeyAliasPostfix.equals(backupKeyTimestamp)) {
            decryptionKey = BACKUP_KEY_ALIAS;
        }

        // Get key and return
        String activeKey = secretKeyFile.getProperty(decryptionKey);

        // Generate SecretKey form Active Key
        SecretKey secretKey = null;
        try {
            secretKey = generateSecretKeyFromKeyString(activeKey);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return secretKey;
    }

    private String getKeyStringForSecretKey(SecretKey aesKey) throws IOException {
        String keyString;
        try (ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
             ObjectOutputStream outputStream = new ObjectOutputStream(byteOutputStream)) {
            outputStream.writeObject(aesKey);
            keyString = new String(Base64Coder.encode(byteOutputStream.toByteArray()));
        }
        return keyString;
    }

    private SecretKey generateSecretKeyFromKeyString(String keyString) throws IOException, ClassNotFoundException {
        byte[] data = Base64Coder.decode(keyString);
        SecretKey secretKey;
        try (ByteArrayInputStream byteInputStream = new ByteArrayInputStream(data);
             ObjectInputStream inputStream = new ObjectInputStream(byteInputStream)) {
            secretKey = (SecretKey) inputStream.readObject();
        }
        return secretKey;
    }

}
