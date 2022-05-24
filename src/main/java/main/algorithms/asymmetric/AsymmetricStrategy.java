package main.algorithms.asymmetric;

import main.KeyType;
import org.bouncycastle.openpgp.PGPKeyPair;

import java.security.KeyPair;

public interface AsymmetricStrategy {
	PGPKeyPair generateKeyPair(int size);

	KeyType getKeyType();
}
