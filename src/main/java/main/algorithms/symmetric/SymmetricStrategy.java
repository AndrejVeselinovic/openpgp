package main.algorithms.symmetric;

import java.util.UUID;

public interface SymmetricStrategy {
	byte[] encryptMessage(String message, UUID keyId);

	String decryptMessage(byte[] encryptedMessage);
}
