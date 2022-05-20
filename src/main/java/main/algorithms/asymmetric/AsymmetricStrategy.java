package main.algorithms.asymmetric;

import java.security.KeyPair;

public interface AsymmetricStrategy {
	KeyPair generateKeyPair(int size);
}
