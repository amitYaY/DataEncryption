package com.fitkart.encryption.rest;

import com.fitkart.encryption.keygenerator.AESKeyGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/app")
public class KeyGeneratorController {

    @Autowired
    private AESKeyGenerator aesKeyGenerator;

    @RequestMapping(value = "/first/active/secretkey/property", method = RequestMethod.POST)
    public String generateFirstSecretKey() {
        return aesKeyGenerator.generateAESKeyWithTimestampSuffixAlias();
    }

    @RequestMapping(value = "/rotate/active/secretkey/property", method = RequestMethod.POST)
    public String rotateKeyInKeyStoreWithTimestampSuffix() {
        return aesKeyGenerator.rotateKeyInKeyStoreWithTimestampSuffix();
    }

}
