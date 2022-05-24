package main;

import lombok.AllArgsConstructor;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.algorithms.symmetric.EncryptionAlgorithm;
import main.repositories.FileRepository;
import main.repositories.Repository;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

	public byte[] encryptMessage(String message, UUID keyId, EncryptionAlgorithm algorithm) {
		return algorithm.encryptMessage(message, keyId);
	}

	public String decryptMessage(byte[] encryptedMessage, EncryptionAlgorithm algorithm) {
		return algorithm.decryptMessage(encryptedMessage);
	}

	private static void flushToFile(byte[] bytes) {
		try {
			ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream("test.txt"));
			armoredOutputStream.write(bytes);
			armoredOutputStream.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) {
		OpenPGP openPGP = new OpenPGP(new FileRepository());
		//		openPGP.generateKeyPair("andrej", "email", "123", KeyPairAlgorithm.ElGamal4096);
//		openPGP.generateKeyPair("andrej", "email@gmail.com", "123", KeyPairAlgorithm.DSA_1024, KeyPairAlgorithm.ElGamal1024);
		//		openPGP.exportPublicKey("public.asc", null);
		//		openPGP.exportPrivateKey("private.asc", null);
		//		openPGP.generateKeyPair("andrej", "email", "123", KeyPairAlgorithm.DSA_1024);
		//		openPGP.getUserKeys().forEach(System.out::println);
		//		openPGP.deleteKeyPair(UUID.fromString("44684ede-3545-4d09-b294-98802a073879"));
		//		openPGP.getUsers().forEach(System.out::println);
				byte[] tests = openPGP.encryptMessage("test", UUID.fromString("1ba79114-df4d-4838-a09e-108869dc1017"), EncryptionAlgorithm.TDESWithEDE);
				flushToFile(tests);
//				String s = openPGP.decryptMessage(tests, EncryptionAlgorithm.TDESWithEDE);
//				System.out.println(s);
	}
}