package main.algorithms.asymmetric;

import main.dtos.KeyType;
import org.bouncycastle.openpgp.PGPKeyPair;

public interface AsymmetricStrategy {
	PGPKeyPair generateKeyPair(int size);

	KeyType getKeyType();
}
