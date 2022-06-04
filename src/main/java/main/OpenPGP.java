package main;

import lombok.AllArgsConstructor;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.algorithms.symmetric.EncryptionAlgorithm;
import main.dtos.UserKeyInfo;
import main.repositories.FileRepository;
import main.repositories.Repository;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

@AllArgsConstructor
public class OpenPGP {
	private final Repository repository;

	private PGPKeyRingGenerator createPGPKeyRingGenerator(PGPKeyPair dsaKeyPair, PGPKeyPair elGamalKeyPair,
			String email, char[] passphrase) {
		try {
			PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build()
					.get(HashAlgorithmTags.SHA1);
			PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
					email, sha1Calc, null, null,
					new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
					new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC")
							.build(passphrase));
			keyRingGen.addSubKey(elGamalKeyPair);
			return keyRingGen;
		} catch (PGPException e) {
			throw new RuntimeException(e);
		}
	}

	public void generateKeyPair(String username, String email, String password, KeyPairAlgorithm dsaAlgorithm,
			KeyPairAlgorithm elGamalAlgorithm) {
		PGPKeyPair dsaKeyPair = dsaAlgorithm.generateKeyPair();
		PGPKeyPair elGamalKeyPair = elGamalAlgorithm.generateKeyPair();
		PGPKeyRingGenerator pgpKeyRingGenerator = createPGPKeyRingGenerator(dsaKeyPair, elGamalKeyPair, email,
				password.toCharArray());
		UUID keyId = repository.persistKeyPair(pgpKeyRingGenerator);
		UserKeyInfo userKeyInfo = new UserKeyInfo(username, password, email, keyId, dsaAlgorithm.getKeyType(),
				elGamalAlgorithm.getKeyType());
		repository.persistUserKeyInfo(userKeyInfo);
	}

	public void readPublicKeyFromFile(String path) throws IOException {
		FileInputStream fileInputStream = new FileInputStream(path);
		byte[] bytes = fileInputStream.readAllBytes();
		fileInputStream.close();
		JcaPGPPublicKeyRing pgpPublicKeys = new JcaPGPPublicKeyRing(bytes);
		Iterator<PGPPublicKey> iterator = pgpPublicKeys.iterator();
		PGPPublicKey signingKey = iterator.next();
		PGPPublicKey encryptionKey = iterator.next();
	}

	public List<UserKeyInfo> getUserKeys() {
		return repository.getUsers();
	}

	public void deleteKeyPair(UUID keyId) {
		repository.deleteKeyPair(keyId);
	}

	public byte[] encrypt(String message, UUID publicKeyUuid, EncryptionAlgorithm encryptionAlgorithm, UUID keyToSignMessageWith, boolean shouldCompress) {
		try {
			return encryptionAlgorithm.encryptMessage(message, publicKeyUuid, keyToSignMessageWith, shouldCompress);
		} catch (IOException | PGPException | GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(byte[] message, String password, UUID privateKeyUuid) {
		return EncryptionAlgorithm.decryptMessage(message, password, privateKeyUuid);
	}

	private static void flushToFile(byte[] bytes) {
		flushToFile(bytes, "test.txt");
	}

	private static void flushToFile(byte[] bytes, String filename) {
		try {
//			ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(filename));
//			armoredOutputStream.write(bytes);
//			armoredOutputStream.close();
			FileOutputStream fileOutputStream = new FileOutputStream(filename);
			fileOutputStream.write(bytes);
			fileOutputStream.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) throws Exception {
		OpenPGP openPGP = new OpenPGP(new FileRepository());

//		openPGP.generateKeyPair("andrej", "email@gmail.com", "123", KeyPairAlgorithm.DSA_1024, KeyPairAlgorithm.ElGamal1024);
//		openPGP.getUserKeys().forEach(System.out::println);
//		openPGP.deleteKeyPair(UUID.fromString("44684ede-3545-4d09-b294-98802a073879"));
//		openPGP.getUserKeys().forEach(System.out::println);

		String message = "test";
		UUID keyPairUuid = UUID.fromString("aeec0789-40c4-4b2e-86c2-4943bbff198e");
		EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.CAST5;
		String password = "123";
		byte[] encryptedBytes = openPGP.encrypt(message, keyPairUuid, encryptionAlgorithm, null, true);
		System.out.println("Successfully encrypted");
		flushToFile(encryptedBytes, "message.txt");
		String decryptedString = openPGP.decrypt(encryptedBytes, password, keyPairUuid);
		System.out.println("Successfully decrypted");
		System.out.println(decryptedString);
	}
}