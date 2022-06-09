package jn180088dva180221d.algorithms.asymmetric;

import org.bouncycastle.openpgp.PGPKeyPair;

public interface AsymmetricStrategy {
	PGPKeyPair generateKeyPair(int size);

	String getKeyType();
}
