package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.repositories.Repository;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

public class TDES implements SymmetricStrategy {

	//	private final Repository repository;

	private final List<SecretKeySpec> secretKeySpec = new LinkedList<>();

	@Override
	public byte[] encryptMessage(String message) {
		byte[] encryptedMessage = message.getBytes();
		for (int i = 0; i < 3; i++) {
			try {
				// generate a key
				KeyGenerator keygen = KeyGenerator.getInstance("DESede");
				keygen.init(112);
				byte[] key = keygen.generateKey().getEncoded();
				SecretKeySpec skeySpec = new SecretKeySpec(key, "DESede");
				this.secretKeySpec.add(skeySpec);

				// initialize the cipher for encrypt mode
				Cipher cipher = Cipher.getInstance("DESede");
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

				encryptedMessage = cipher.doFinal(encryptedMessage);
			} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
					 IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}
		return encryptedMessage;
	}

	@Override
	public String decryptMessage(byte[] encryptedMessage) {
		byte[] decryptedMessage = encryptedMessage;
		for (int i = 2; i >= 0; i--) {
			try {
				final Cipher cipher = Cipher.getInstance("desede");
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec.get(i));
				decryptedMessage = cipher.doFinal(decryptedMessage);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return new String(decryptedMessage);
	}
}
