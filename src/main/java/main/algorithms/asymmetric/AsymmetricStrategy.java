package main.algorithms.asymmetric;

import main.KeyType;

import java.security.KeyPair;

public interface AsymmetricStrategy {
	KeyPair generateKeyPair(int size);

	KeyType getKeyType();
}
