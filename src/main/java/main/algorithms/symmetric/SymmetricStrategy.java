package main.algorithms.symmetric;

public interface SymmetricStrategy {
	byte[] encryptMessage(String message);

	String decryptMessage(byte[] encryptedMessage);
}
