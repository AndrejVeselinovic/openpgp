package main.algorithms.asymmetric;

import org.bouncycastle.openpgp.PGPKeyPair;

public interface AsymmetricStrategy {
	PGPKeyPair generateKeyPair(int size);

	String getKeyType();
}
