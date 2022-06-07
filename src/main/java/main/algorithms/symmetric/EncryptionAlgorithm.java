package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.repositories.FileRepository;
import main.repositories.Repository;
import main.utils.PGPDecrypt;
import main.utils.PGPEncrypt;
import main.utils.PGPSign;
import main.utils.PGPVerify;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@AllArgsConstructor
public enum EncryptionAlgorithm {
	TRIPLE_DES(new TripleDes()), CAST5(new Cast5());

	private static final String SIGNATURE_TAG = "*signed*";
	private static final int UUID_LENGTH = 36;

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

	public byte[] encryptMessage(String message, Collection<UUID> keyIds, boolean shouldCompress,
			UUID keyToSignMessageWith, String signingKeyPassword, boolean shouldEncode)
			throws IOException, PGPException, GeneralSecurityException {
		byte[] bytesToEncrypt = message.getBytes();

		PGPPrivateKey pgpPrivateKey;
		if (keyToSignMessageWith != null) {
			SecretKeyInfo secretSigningKeyInfo = repository.getSecretSigningKey(keyToSignMessageWith);
			pgpPrivateKey = fromPGPSecretKey(secretSigningKeyInfo.getSecretKey(), signingKeyPassword);
			bytesToEncrypt = PGPSign.sign(bytesToEncrypt, pgpPrivateKey);
			bytesToEncrypt = Arrays.concatenate(keyToSignMessageWith.toString().getBytes(), bytesToEncrypt);
			bytesToEncrypt = Arrays.concatenate(SIGNATURE_TAG.getBytes(), bytesToEncrypt);
		}

		int algorithmTag = this.symmetricEncryptionStrategy.getSymmetricKeyAlgorithmTag();
		Collection<PGPPublicKey> publicKeyInfoCollection = keyIds.stream()
				.map(repository::getPublicEncryptionKey)
				.map(PublicKeyInfo::getPublicKey)
				.collect(Collectors.toList());
		bytesToEncrypt = PGPEncrypt.encrypt(bytesToEncrypt, publicKeyInfoCollection, algorithmTag,
				shouldCompress);
		if (shouldEncode) {
			bytesToEncrypt = Base64.encodeBase64(bytesToEncrypt);
		}
		return bytesToEncrypt;
	}

	public static String decryptMessage(byte[] encryptedData, String password, UUID keyId)
			throws PGPException, IOException {
		boolean shouldDecode = Base64.isBase64(encryptedData);
		if (shouldDecode) {
			encryptedData = Base64.decodeBase64(encryptedData);
		}
		SecretKeyInfo secretKeyInfo = repository.getSecretEncryptionKey(keyId);
		PGPSecretKey secretKey = secretKeyInfo.getSecretKey();
		PGPPrivateKey pgpPrivateKey = fromPGPSecretKey(secretKey, password);

		byte[] decrypt = PGPDecrypt.decrypt(encryptedData, pgpPrivateKey);
		int tagSize = UUID_LENGTH + SIGNATURE_TAG.getBytes().length;
		if (decrypt.length > tagSize) {
			byte[] signatureTag = Arrays.copyOfRange(decrypt, 0, SIGNATURE_TAG.getBytes().length);
			if (new String(signatureTag).equals(SIGNATURE_TAG)) {
				byte[] uuidBytes = Arrays.copyOfRange(decrypt, SIGNATURE_TAG.getBytes().length, tagSize);
				UUID signingKey = UUID.fromString(new String(uuidBytes));
				PublicKeyInfo publicSigningKey = repository.getPublicSigningKey(signingKey);
				decrypt = Arrays.copyOfRange(decrypt, tagSize, decrypt.length);
				decrypt = PGPVerify.verify(decrypt, publicSigningKey.getPublicKey());
			}
		}

		return new String(decrypt);
	}

	public static EncryptionAlgorithm[] getEncryptionAlgorithms() {
		return new EncryptionAlgorithm[] { TRIPLE_DES, CAST5 };
	}
}
