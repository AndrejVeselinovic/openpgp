package main.algorithms.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class DSAStrategy implements AsymmetricStrategy {
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
