package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.repositories.Repository;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@AllArgsConstructor
public class TDES implements SymmetricStrategy {

	private final Repository repository;

	private static final String ALGORITHM = "DESede";
	private static final int KEY_SIZE = 112;
	private static final int UUID_LENGTH = 36;

	//	private final List<SecretKeySpec> secretKeySpec = new LinkedList<>();

	@Override
	public byte[] encryptMessage(String message) {
		UUID sessionId = UUID.randomUUID();
		byte[] encryptedMessage = message.getBytes();
		for (int i = 0; i < 3; i++) {
			try {
				// generate a key
				KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
				keygen.init(KEY_SIZE);
				byte[] key = keygen.generateKey().getEncoded();
				repository.persistSessionKey(sessionId, i, key);

				SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

				// initialize the cipher for encrypt mode
				Cipher cipher = Cipher.getInstance(ALGORITHM);
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

				encryptedMessage = cipher.doFinal(encryptedMessage);
			} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
					 IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}
		byte[] sessionIdBytes = sessionId.toString().getBytes();
		ByteBuffer byteBuffer = ByteBuffer.allocate(encryptedMessage.length + sessionIdBytes.length);
		byteBuffer.put(sessionIdBytes);
		byteBuffer.put(encryptedMessage);
		return byteBuffer.array();
	}

	@Override
	public String decryptMessage(byte[] encryptedMessage) {
		byte[] sessionIdBytes = new byte[UUID_LENGTH];
		System.arraycopy(encryptedMessage, 0, sessionIdBytes, 0, UUID_LENGTH);
		UUID sessionId = UUID.fromString(new String(sessionIdBytes));

		int encryptedMessageLength = encryptedMessage.length - UUID_LENGTH;
		byte[] decryptedMessage = new byte[encryptedMessageLength];
		System.arraycopy(encryptedMessage, UUID_LENGTH, decryptedMessage, 0, encryptedMessageLength);

		for (int i = 2; i >= 0; i--) {
			try {
				byte[] key = repository.retrieveSessionKey(sessionId, i);
				SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

				final Cipher cipher = Cipher.getInstance(ALGORITHM);
				cipher.init(Cipher.DECRYPT_MODE, skeySpec);
				decryptedMessage = cipher.doFinal(decryptedMessage);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		this.repository.deleteSessionKey(sessionId);

		return new String(decryptedMessage);
	}
}
