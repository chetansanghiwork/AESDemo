package com.example.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AesDemoApplicationTests {

	private static Logger logger = LoggerFactory.getLogger(AesDemoApplicationTests.class);
	
	@Test
	void testAESEncryptAndDecrypt() throws Exception{
			String plainText = "ur=123456789012345ad=123456789012";
			String password = "usingaes";
			String salt = "12345678";
			IvParameterSpec ivParameterSpec = AesApi.generateIv();
			SecretKey key = AesApi.getKeyFromPassword(password, salt);

			String cipherText = AesApi.encryptPasswordBased(plainText, key, ivParameterSpec);
			logger.info("cipherText === " + cipherText);
			String decryptedCipherText = AesApi.decryptPasswordBased(cipherText, key, ivParameterSpec);
			logger.info("decryptedCipherText === " + decryptedCipherText);
	}

}
