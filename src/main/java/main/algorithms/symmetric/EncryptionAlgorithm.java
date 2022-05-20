package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.repositories.FileRepository;

@AllArgsConstructor
public enum EncryptionAlgorithm {
	TDESWithEDE(new TDES());

	private final SymmetricStrategy strategy;

	public byte[] encryptMessage(String message) {
		return this.strategy.encryptMessage(message);
	}

	public String decryptMessage(byte[] encryptedMessage) {
		return this.strategy.decryptMessage(encryptedMessage);
	}
}
