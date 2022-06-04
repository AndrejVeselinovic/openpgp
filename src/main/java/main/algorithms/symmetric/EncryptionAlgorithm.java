package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.repositories.FileRepository;
import main.repositories.Repository;
import main.workingexamples.HMAC_SHA1;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.UUID;

@AllArgsConstructor
public enum EncryptionAlgorithm {
	TRIPLE_DES(new TripleDes()),
	CAST5(new Cast5());


	private final SymmetricEncryptionStrategy symmetricEncryptionStrategy;
	private static final Repository repository = new FileRepository();


	private static PGPPrivateKey fromPGPSecretKey(PGPSecretKey secretKey, String password) {
		try {
			return secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
							.build(password.toCharArray()));
		} catch (PGPException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] encryptMessage(String message, UUID keyId, UUID keyToSignMessageWith, boolean shouldCompress)
			throws IOException, PGPException, GeneralSecurityException {
		PublicKeyInfo publicEncryptionKeyInfo = repository.getPublicEncryptionKey(keyId);
		byte[] bytesToEncrypt = message.getBytes();
		if (keyToSignMessageWith != null) {
			SecretKeyInfo secretSigningKeyInfo = repository.getSecretSigningKey(keyToSignMessageWith);
//			PGPPrivateKey pgpPrivateKey = fromPGPSecretKey(secretSigningKeyInfo.getSecretKey(), "123");
//			PrivateKey privateKey = new JcaPGPKeyConverter().getPrivateKey(pgpPrivateKey);
//			byte[] hmacBytes = HMAC_SHA1.generateSignature(privateKey, bytesToEncrypt);

			byte[] hmacBytes = HMAC_SHA1.generateSignature(secretSigningKeyInfo.getSecretKey().getEncoded(),
					bytesToEncrypt);

			bytesToEncrypt = Arrays.concatenate(bytesToEncrypt, hmacBytes);
		}
		return this.symmetricEncryptionStrategy.encrypt(bytesToEncrypt, publicEncryptionKeyInfo.getPublicKey(), shouldCompress);
	}

	public static String decryptMessage(byte[] encryptedData, String password, UUID keyId) {
		SecretKeyInfo secretKeyInfo = repository.getSecretEncryptionKey(keyId);
		PGPSecretKey secretKey = secretKeyInfo.getSecretKey();
		PGPPrivateKey pgpPrivateKey = fromPGPSecretKey(secretKey, password);

		byte[] signedMessageBytes;
		try {
			signedMessageBytes = DecryptionAlgorithm.decrypt(encryptedData, pgpPrivateKey);
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e);
		}
		return new String(signedMessageBytes);
	}
}
