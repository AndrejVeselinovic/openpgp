package main.algorithms.symmetric;

public interface SymmetricStrategy {
	byte[] encryptMessage(String message, String keyId);

	String decryptMessage(byte[] encryptedMessage, String keyId);
}
