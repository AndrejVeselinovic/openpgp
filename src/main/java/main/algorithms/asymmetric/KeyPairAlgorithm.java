package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import main.KeyType;
import org.bouncycastle.openpgp.PGPKeyPair;

import java.security.KeyPair;

@AllArgsConstructor
public enum KeyPairAlgorithm {
	DSA_1024(1024, new DSAStrategy(KeyType.DSA1024)),
	DSA_2048(2048, new DSAStrategy(KeyType.DSA2048)),
	ElGamal1024(1024, new ElGamalStrategy(KeyType.ElGamal1024)),
	ElGamal2048(2048, new ElGamalStrategy(KeyType.ElGamal2048)),
	ElGamal4096(4096, new ElGamal4096Strategy(KeyType.ElGamal4096));

	private final int size;
	private final AsymmetricStrategy asymmetricStrategy;

	public PGPKeyPair generateKeyPair() {
		return this.asymmetricStrategy.generateKeyPair(this.size);
	}

	public KeyType getKeyType(){
		return this.asymmetricStrategy.getKeyType();
	}
}
