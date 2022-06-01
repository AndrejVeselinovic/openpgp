package main.workingexamples;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TripleDESEncryptor {

	private static final String UNICODE_FORMAT = "UTF8";
	private static final String DESEDE_ECB_ENCRYPTION_SCHEME = "DESede/ECB/NoPadding";
	private static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
	private static String BOUNCY_CASTLE_FIPS_PROVIDER = "BC";
	private final Cipher cipher;
	private final SecretKey key;

	public TripleDESEncryptor(byte[] encryptionKey) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			cipher = Cipher.getInstance(DESEDE_ECB_ENCRYPTION_SCHEME, BOUNCY_CASTLE_FIPS_PROVIDER);
			key = SecretKeyFactory.getInstance(DESEDE_ENCRYPTION_SCHEME, BOUNCY_CASTLE_FIPS_PROVIDER)
					.generateSecret(new DESedeKeySpec(encryptionKey));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] encrypt(String unencryptedString)
			throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] paddedPlainText = padWithZeroBytes(unencryptedString.getBytes(UNICODE_FORMAT));
		return cipher.doFinal(paddedPlainText);
	}

	private byte[] padWithZeroBytes(byte[] unencryptedString) {
		return Arrays.copyOf(unencryptedString, roundUpToMultipleOf8(unencryptedString.length));
	}

	private int roundUpToMultipleOf8(int x) {
		return ((x + 7) & (-8));
	}
}