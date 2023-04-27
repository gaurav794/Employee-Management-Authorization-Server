package com.gaurav.authorizationserver.config.keys;

import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

public class JwkKeys {

    public static RSAKey generateRSAkey() throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keys = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keys.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keys.getPrivate();

        return new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).keyID(UUID.randomUUID().toString()).build();
    }
}
