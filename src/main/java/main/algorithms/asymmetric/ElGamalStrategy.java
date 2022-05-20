package main.algorithms.asymmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.UUID;

public class ElGamalStrategy implements AsymmetricStrategy {
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	@Override
	public KeyPair generateKeyPair(int size) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL");
			keyPairGenerator.initialize(size);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			Cipher cipher = Cipher.getInstance("elgamal");
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			byte[] bytes = cipher.doFinal(UUID.randomUUID().toString().getBytes());
			return keyPair;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
				 BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}
}
