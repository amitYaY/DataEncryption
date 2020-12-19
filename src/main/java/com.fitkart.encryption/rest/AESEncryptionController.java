package com.fitkart.encryption.rest;

import com.fitkart.encryption.keystore.KeyStoreService;
import com.fitkart.encryption.service.AESCipherService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/app")
public class AESEncryptionController {

    @Autowired
    private AESCipherService aesCipherService;

    @Autowired
    private KeyStoreService keyStoreService;

    private static final String DELIMITER = "alias:";

    // Encryption Strategy #3
    @RequestMapping(value = "/encrypt/aes/alias/active", method = RequestMethod.POST)
    public ResponseEntity<String> encryptMessageWithAliasActive(@RequestBody String message) {

        String responseMsg;
        String keySuffix = null;
        SecretKey secretKey = null;

        byte[] aadData = "random".getBytes();
        try {
            Map<String, SecretKey> encryptionKeySet = keyStoreService.getSecretKeyForEncryption();
            Set<String> keySet = encryptionKeySet.keySet();
            // keySet Size will be 1.
            for(String key : keySet) {
                keySuffix = key;
                secretKey = encryptionKeySet.get(key);
            }
            responseMsg = aesCipherService.encryptMessageWithAliasActive(message, secretKey, aadData, keySuffix);
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
        }
        return ResponseEntity.ok(responseMsg);
    }

    // Decryption Strategy #3
    @RequestMapping(value = "/decrypt/aes/alias/timestamp", method = RequestMethod.POST)
    public ResponseEntity<String> decryptMessageWithAlias(@RequestBody String cipherTextInput) {

        String aliasNameSuffix = "Key1";
        String cipherText = cipherTextInput;

        String[] cipherArr = cipherTextInput.split(DELIMITER);
        if(cipherArr.length > 1) {
            aliasNameSuffix = cipherArr[1];
            cipherText = cipherArr[0];
        }

        String responseMsg;
        byte[] aadData = "random".getBytes();
        try {
            SecretKey aesKey = keyStoreService.getSecretKeyForDecryption(aliasNameSuffix);
            responseMsg = aesCipherService.decryptCipherWithAlias(cipherText, aesKey, aadData);
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
        }
        return ResponseEntity.ok(responseMsg);
    }

}
