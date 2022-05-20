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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@AllArgsConstructor
public class TDES implements SymmetricStrategy {

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private final Repository repository;

	private static final String ALGORITHM = "DESede";
	private static final int KEY_SIZE = 112;
	private static final int ENCRYPTED_UUID_LENGTH = 256;

	@Override
	public byte[] encryptMessage(String message, String keyId) {
		UUID sessionId = UUID.randomUUID();
		byte[] encryptedMessage = message.getBytes();
		for (int i = 0; i < 3; i++) {
			try {
				// generate a key
				KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
				keygen.init(KEY_SIZE);
				byte[] key = keygen.generateKey().getEncoded();
				repository.persistSessionKey(sessionId, i, key);

				SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);

				// initialize the cipher for encrypt mode
				Cipher cipher = Cipher.getInstance(ALGORITHM);
				cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

				encryptedMessage = cipher.doFinal(encryptedMessage);

			} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
					 IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		try {
			byte[] publicKeyBytes = this.repository.retrievePublicKey(UUID.fromString(keyId));
			Cipher elgamalCipher = Cipher.getInstance("elgamal");
			PublicKey publicKey = KeyFactory.getInstance("elgamal").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			elgamalCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedSessionId = elgamalCipher.doFinal(sessionId.toString().getBytes());
			ByteBuffer byteBuffer = ByteBuffer.allocate(encryptedMessage.length + encryptedSessionId.length);
			byteBuffer.put(encryptedSessionId);
			byteBuffer.put(encryptedMessage);

			return byteBuffer.array();
		} catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
				 InvalidKeySpecException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String decryptMessage(byte[] encryptedMessage, String keyId) {
		UUID sessionId;

		byte[] encryptedSessionIdBytes = new byte[ENCRYPTED_UUID_LENGTH];
		System.arraycopy(encryptedMessage, 0, encryptedSessionIdBytes, 0, ENCRYPTED_UUID_LENGTH);
		try {
			byte[] privateKeyBytes = this.repository.retrievePrivateKey(UUID.fromString(keyId));
			Cipher elgamalCipher = Cipher.getInstance("elgamal");
			PrivateKey privateKey = KeyFactory.getInstance("elgamal").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
			elgamalCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] sessionIdBytes = elgamalCipher.doFinal(encryptedSessionIdBytes);
			sessionId = UUID.fromString(new String(sessionIdBytes));
		} catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
				 InvalidKeySpecException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}

		int encryptedMessageLength = encryptedMessage.length - ENCRYPTED_UUID_LENGTH;
		byte[] decryptedMessage = new byte[encryptedMessageLength];
		System.arraycopy(encryptedMessage, ENCRYPTED_UUID_LENGTH, decryptedMessage, 0, encryptedMessageLength);

		for (int i = 2; i >= 0; i--) {
			try {
				byte[] key = repository.retrieveSessionKey(sessionId, i);
				SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);

				final Cipher cipher = Cipher.getInstance(ALGORITHM);
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
				decryptedMessage = cipher.doFinal(decryptedMessage);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		this.repository.deleteSessionKey(sessionId);

		return new String(decryptedMessage);
	}
}
