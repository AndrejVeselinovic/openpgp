package algorithms;

import java.security.*;

public class DSAStrategy implements Strategy{
	@Override
	public KeyPair generateKeyPair(int size) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
			generator.initialize(size);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
