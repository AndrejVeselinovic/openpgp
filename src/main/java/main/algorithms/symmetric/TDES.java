package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.KeyType;
import main.SecretKeyInfo;
import main.repositories.Repository;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@AllArgsConstructor
public class TDES implements SymmetricStrategy {

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private final Repository repository;

	private static final String ALGORITHM = "DESede";
	private static final int KEY_SIZE = 112;
	private static final int UUID_LENGTH = 36;
	private static final Map<KeyType, Integer> ENCRYPTED_UUID_LENGTH = new HashMap<>() {{
		put(KeyType.ElGamal1024, 256);
		put(KeyType.ElGamal2048, 512);
		put(KeyType.ElGamal4096, 128);
	}};

//	public byte[] encryptMessage(String message, UUID keyId) {
//		UUID sessionId = UUID.randomUUID();
//		byte[] encryptedMessage = message.getBytes();
//		for (int i = 0; i < 3; i++) {
//			try {
//				// generate a key
//				KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
//				keygen.init(KEY_SIZE);
//				byte[] key = keygen.generateKey().getEncoded();
//				repository.persistSessionKey(sessionId, i, key);
//
//				SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
//
//				// initialize the cipher for encrypt mode
//				Cipher cipher = Cipher.getInstance(ALGORITHM);
//				cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
//
//				encryptedMessage = cipher.doFinal(encryptedMessage);
//
//			} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
//					 IllegalBlockSizeException | BadPaddingException e) {
//				throw new RuntimeException(e);
//			}
//		}
//
//		try {
//			byte[] encryptedSessionId = sessionId.toString().getBytes();
//			PublicKeyInfo publicKeyInfo = this.repository.retrievePublicEncryptionKey(keyId);
//			Cipher elgamalCipher = Cipher.getInstance("elgamal");
//			JcaPGPKeyConverter converter = new JcaPGPKeyConverter();
//			converter.setProvider("BC");
//			PublicKey publicKey = converter.getPublicKey(publicKeyInfo.getPublicKey());
//			//			PublicKey publicKey = KeyFactory.getInstance("elgamal")
////					.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getPublicKey().getEncoded()));
//			elgamalCipher.init(Cipher.ENCRYPT_MODE, publicKey);
//			encryptedSessionId = elgamalCipher.doFinal(encryptedSessionId);
//
//			byte[] keyIdBytes = keyId.toString().getBytes();
//			ByteBuffer byteBuffer = ByteBuffer.allocate(
//					encryptedMessage.length + encryptedSessionId.length + keyIdBytes.length);
//			byteBuffer.put(keyIdBytes);
//			byteBuffer.put(encryptedSessionId);
//			byteBuffer.put(encryptedMessage);
//
//			return byteBuffer.array();
//		} catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
//				 InvalidKeyException | PGPException e) {
//			throw new RuntimeException(e);
//		}
//	}

	@Override
	public byte[] encryptMessage(String message, UUID keyId) {
		byte[] messageBytes = message.getBytes();
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
			keyGenerator.init(168);
			SecretKey secretKey = keyGenerator.generateKey();

			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));

			cipher.init(true, new KeyParameter(secretKey.getEncoded()));
			byte[] result = new byte[cipher.getOutputSize(messageBytes.length)];
			int numberOfCopiedBytes = cipher.processBytes(messageBytes, 0, messageBytes.length, result, 0);
			cipher.doFinal(result, numberOfCopiedBytes);
			return result;
		} catch (NoSuchAlgorithmException | InvalidCipherTextException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String decryptMessage(byte[] encryptedMessage) {
		UUID sessionId;
		int cursor = 0;

		byte[] keyIdBytes = new byte[UUID_LENGTH];
		System.arraycopy(encryptedMessage, cursor, keyIdBytes, 0, UUID_LENGTH);
		cursor += UUID_LENGTH;
		SecretKeyInfo secretKeyInfo = this.repository.retrievePrivateEncryptionKey(
				UUID.fromString(new String(keyIdBytes)));

		int encryptedUUIDLength = ENCRYPTED_UUID_LENGTH.get(secretKeyInfo.getKeyType());
		byte[] encryptedSessionIdBytes = new byte[encryptedUUIDLength];
		System.arraycopy(encryptedMessage, cursor, encryptedSessionIdBytes, 0, encryptedUUIDLength);
		cursor += encryptedUUIDLength;

		try {
			Cipher elgamalCipher = Cipher.getInstance("elgamal");
			PrivateKey privateKey = KeyFactory.getInstance("elgamal")
					.generatePrivate(new PKCS8EncodedKeySpec(secretKeyInfo.getSecretKey().getEncoded()));
			elgamalCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] sessionIdBytes = elgamalCipher.doFinal(encryptedSessionIdBytes);
			sessionId = UUID.fromString(new String(sessionIdBytes));
		} catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
				 InvalidKeySpecException | InvalidKeyException | IOException e) {
			throw new RuntimeException(e);
		}

		int encryptedMessageLength = encryptedMessage.length - cursor;
		byte[] decryptedMessage = new byte[encryptedMessageLength];
		System.arraycopy(encryptedMessage, cursor, decryptedMessage, 0, encryptedMessageLength);

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
