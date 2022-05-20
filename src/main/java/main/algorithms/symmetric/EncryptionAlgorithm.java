package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.repositories.FileRepository;

@AllArgsConstructor
public enum EncryptionAlgorithm {
	TDESWithEDE(new TDES(new FileRepository()));

	private final SymmetricStrategy strategy;

	public byte[] encryptMessage(String message, String keyId) {
		return this.strategy.encryptMessage(message, keyId);
	}

	public String decryptMessage(byte[] encryptedMessage) {
		return this.strategy.decryptMessage(encryptedMessage);
	}
}
