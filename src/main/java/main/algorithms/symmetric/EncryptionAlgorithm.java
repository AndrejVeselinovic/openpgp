package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.dtos.DecryptionInfo;
import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.dtos.UserKeyInfo;
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
import java.security.Security;
import java.util.Collection;
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
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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

		if (keyToSignMessageWith != null) {
			SecretKeyInfo secretSigningKeyInfo = repository.getSecretSigningKey(keyToSignMessageWith);
			PGPPrivateKey pgpPrivateKey = fromPGPSecretKey(secretSigningKeyInfo.getSecretKey(), signingKeyPassword);
			bytesToEncrypt = PGPSign.sign(bytesToEncrypt, pgpPrivateKey);
			bytesToEncrypt = prependSignatureTag(keyToSignMessageWith, bytesToEncrypt);
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

	private byte[] prependSignatureTag(UUID keyToSignMessageWith, byte[] bytesToEncrypt) {
		bytesToEncrypt = Arrays.concatenate(keyToSignMessageWith.toString().getBytes(), bytesToEncrypt);
		bytesToEncrypt = Arrays.concatenate(SIGNATURE_TAG.getBytes(), bytesToEncrypt);
		return bytesToEncrypt;
	}

	public static DecryptionInfo decryptMessage(byte[] encryptedData, String password, UUID keyId)
			throws PGPException, IOException {
		boolean shouldDecode = Base64.isBase64(encryptedData);
		if (shouldDecode) {
			encryptedData = Base64.decodeBase64(encryptedData);
		}
		SecretKeyInfo secretKeyInfo = repository.getSecretEncryptionKey(keyId);
		PGPSecretKey secretKey = secretKeyInfo.getSecretKey();
		PGPPrivateKey pgpPrivateKey = fromPGPSecretKey(secretKey, password);

		byte[] messageBytes = PGPDecrypt.decrypt(encryptedData, pgpPrivateKey);
		UserKeyInfo signingInfo = null;
		int tagSize = UUID_LENGTH + SIGNATURE_TAG.getBytes().length;
		if (messageBytes.length > tagSize) {
			byte[] signatureTag = Arrays.copyOfRange(messageBytes, 0, SIGNATURE_TAG.getBytes().length);
			if (new String(signatureTag).equals(SIGNATURE_TAG)) {
				byte[] uuidBytes = Arrays.copyOfRange(messageBytes, SIGNATURE_TAG.getBytes().length, tagSize);
				UUID signingKey = UUID.fromString(new String(uuidBytes));
				PublicKeyInfo publicSigningKey;
				try {
					publicSigningKey = repository.getPublicSigningKey(signingKey);
				} catch(Exception e) {
					throw new RuntimeException("Missing public key for verifying signature");
				}
				messageBytes = Arrays.copyOfRange(messageBytes, tagSize, messageBytes.length);
				messageBytes = PGPVerify.verify(messageBytes, publicSigningKey.getPublicKey());
				signingInfo = repository.getUserKeyInfo(signingKey);
			}
		}

		return new DecryptionInfo(signingInfo, new String(messageBytes));
	}

	public static EncryptionAlgorithm[] getEncryptionAlgorithms() {
		return new EncryptionAlgorithm[] { TRIPLE_DES, CAST5 };
	}
}
