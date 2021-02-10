package com.example.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.springframework.stereotype.Component;

import org.apache.commons.codec.binary.Hex;

@Component
public class AesApi {

	private static Logger logger = LoggerFactory.getLogger(AesApi.class);
	
	
	//Hex.encodeHexString( bytes )
	
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        logger.info("generateKey === " + key);
        return key;
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
            .getEncoded(), "AES");
        logger.info("getKeyFromPassword === " + secret);
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
    		throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
    		InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    	Cipher cipher = Cipher.getInstance(algorithm);
    	cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    	byte[] cipherText = cipher.doFinal(input.getBytes());
    	
    	String cipherTextStr = Hex.encodeHexString(cipherText);
    	logger.info("encrypt --> Hex version:  length = " + cipherTextStr.length() + ", value = " + cipherTextStr);
    	
    	String base64VersionTextStr = Base64.getEncoder().encodeToString(cipherText);

    	logger.info("encrypt --> Base64 version:  length = " + base64VersionTextStr.length() + ", value = " + base64VersionTextStr);
    	
        return base64VersionTextStr;    	
    	
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
    		throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
    		InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    	Cipher cipher = Cipher.getInstance(algorithm);
    	cipher.init(Cipher.DECRYPT_MODE, key, iv);
    	byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
    	return new String(plainText);
    }

    
    public static String encryptPasswordBased(String plainText, SecretKey key, IvParameterSpec iv)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        
    	String cipherTextStr = Hex.encodeHexString(cipherText);
    	
    	logger.info("encryptPasswordBased --> Hex version:  length = " + cipherTextStr.length() + ", value = " + cipherTextStr);
        
    	String base64VersionTextStr = Base64.getEncoder().encodeToString(cipherText);

    	logger.info("encryptPasswordBased --> Base64 version:  length = " + base64VersionTextStr.length() + ", value = " + base64VersionTextStr);
    	
        return base64VersionTextStr;
    }

    public static String decryptPasswordBased(String cipherText, SecretKey key, IvParameterSpec iv)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
        InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(Base64.getDecoder()
            .decode(cipherText)));
    }

}