package algorithms;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum KeyPairAlgorithm {
	DSA_1024(1024, new DSAStrategy()),
	DSA_2048(2048, new DSAStrategy()),
	ElGamal1024(1024, new ElGamalStrategy()),
	ElGamal2048(2048, new ElGamalStrategy()),
	ElGamal4096(4096, new ElGamalStrategy());

	private final int size;
	private final Strategy strategy;

	public void generateKeyPair() {
		this.strategy.generateKeyPair(this.size);
	}
}
