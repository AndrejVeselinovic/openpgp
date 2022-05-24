package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.repositories.FileRepository;

import java.util.UUID;

@AllArgsConstructor
public enum EncryptionAlgorithm {
	TDESWithEDE(new TDES(new FileRepository()));

	private final SymmetricStrategy strategy;

	public byte[] encryptMessage(String message, UUID keyId) {
		return this.strategy.encryptMessage(message, keyId);
	}

	public String decryptMessage(byte[] encryptedMessage) {
		return this.strategy.decryptMessage(encryptedMessage);
	}
}
