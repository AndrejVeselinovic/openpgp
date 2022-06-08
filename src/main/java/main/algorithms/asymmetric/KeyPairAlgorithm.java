package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.openpgp.PGPKeyPair;

@AllArgsConstructor
public enum KeyPairAlgorithm {
	DSA_1024(1024, new DSAStrategy()),
	DSA_2048(2048, new DSAStrategy()),
	ElGamal1024(1024, new ElGamalStrategy()),
	ElGamal2048(2048, new ElGamalStrategy()),
	ElGamal4096(4096, new ElGamal4096Strategy());

	private final int size;
	@Getter
	private final AsymmetricStrategy asymmetricStrategy;

	public PGPKeyPair generateKeyPair() {
		return this.asymmetricStrategy.generateKeyPair(this.size);
	}

	public String getKeyType(){
		return this.asymmetricStrategy.getKeyType();
	}

	public static KeyPairAlgorithm[] getSigningAlgorithms() {
		return new KeyPairAlgorithm[]{DSA_1024, DSA_2048};
	}

	public static KeyPairAlgorithm[] getEncryptionAlgorithms() {
		return new KeyPairAlgorithm[]{ElGamal1024, ElGamal2048, ElGamal4096};
	}
}
