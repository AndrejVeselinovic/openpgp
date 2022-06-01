package main.algorithms.symmetric;

import lombok.AllArgsConstructor;
import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.repositories.FileRepository;
import main.repositories.Repository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.util.UUID;

@AllArgsConstructor
public enum EncryptionAlgorithm {
	TDESWithEDE(new TripleDes());

	private final SymmetricEncryptionStrategy symmetricEncryptionStrategy;
	private static final Repository repository = new FileRepository();



	public byte[] encryptMessage(String message, UUID keyId) {
		PublicKeyInfo publicKeyInfo = repository.retrievePublicEncryptionKey(keyId);
		return this.symmetricEncryptionStrategy.encryptMessage(message.getBytes(), publicKeyInfo.getPublicKey());
	}

	public static String decryptMessage(byte[] encryptedData, String password, UUID keyId) {
		try{
			SecretKeyInfo secretKeyInfo = repository.retrievePrivateEncryptionKey(keyId);
			PGPSecretKey secretKey = secretKeyInfo.getSecretKey();
			PGPPrivateKey pgpPrivateKey = secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
							.build(password.toCharArray()));

			byte[] messageBytes = DecryptionAlgorithm.decrypt(encryptedData, pgpPrivateKey);
			return new String(messageBytes);
		} catch (PGPException e) {
			throw new RuntimeException(e);
		}
	}
}
