package main;

import lombok.AllArgsConstructor;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.algorithms.symmetric.EncryptionAlgorithm;
import main.algorithms.symmetric.TDES;
import main.repositories.FileRepository;
import main.repositories.Repository;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import workingexamples.PGPEncryptionExampleForSO;
import workingexamples.PgpImpl;
import workingexamples.TripleDESEncryptor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
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

	public byte[] encrypt(UUID keyId) throws Exception {
		PublicKeyInfo publicKeyInfo = this.repository.retrievePublicEncryptionKey(keyId);
		return PgpImpl.encrypt("Test".getBytes(), publicKeyInfo.getPublicKey());
	}

	public byte[] testEncrypt(UUID keyId, byte[] messageToEncrypt) {
		PublicKeyInfo publicKeyInfo = this.repository.retrievePublicEncryptionKey(keyId);
		try {
			return PGPEncryptionExampleForSO.createEncryptedData(publicKeyInfo.getPublicKey(),
					messageToEncrypt);
		} catch (PGPException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] testDecrypt(UUID keyId, byte[] encryptedData) throws PGPException, IOException {
		SecretKeyInfo secretKeyInfo = this.repository.retrievePrivateEncryptionKey(keyId);
		PGPSecretKey secretKey = secretKeyInfo.getSecretKey();
		PGPPrivateKey pgpPrivateKey = secretKey.extractPrivateKey(
				new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
						.build("123".toCharArray()));

		return PGPEncryptionExampleForSO.extractPlainTextData(pgpPrivateKey, encryptedData);
	}

	public void test() throws PGPException, InvalidAlgorithmParameterException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException,
			NoSuchAlgorithmException, NoSuchProviderException {
		byte[] keyBytes = PGPUtil.makeRandomKey(SymmetricKeyAlgorithmTags.TRIPLE_DES, new SecureRandom());
		flushToFile(keyBytes, "key.asc");
		Cipher cipher = Cipher.getInstance("desede");
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "desede");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		byte[] encryptedBytes = cipher.doFinal("test".getBytes());
		byte[] bytes = this.repository.retrievePublicKey(UUID.fromString("aeec0789-40c4-4b2e-86c2-4943bbff198e"));
		flushToFile(encryptedBytes);
	}

	public String decryptMessage(byte[] encryptedMessage, EncryptionAlgorithm algorithm) {
		return algorithm.decryptMessage(encryptedMessage);
	}

	private static void flushToFile(byte[] bytes) {
		flushToFile(bytes, "test.txt");
	}

	private static void flushToFile(byte[] bytes, String filename) {
		try {
			ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(filename));
			armoredOutputStream.write(bytes);
			armoredOutputStream.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) throws Exception {
		OpenPGP openPGP = new OpenPGP(new FileRepository());
		//		openPGP.generateKeyPair("andrej", "email@gmail.com", "123", KeyPairAlgorithm.DSA_1024, KeyPairAlgorithm.ElGamal4096);
		//		flushToFile(openPGP.encryptMessage("test",null, EncryptionAlgorithm.TDESWithEDE));
		//		openPGP.exportPublicKey("public.asc", null);
		//		openPGP.exportPrivateKey("private.asc", null);
		//		openPGP.generateKeyPair("andrej", "email", "123", KeyPairAlgorithm.DSA_1024);
		//		openPGP.getUserKeys().forEach(System.out::println);
		//		openPGP.deleteKeyPair(UUID.fromString("44684ede-3545-4d09-b294-98802a073879"));
		//		openPGP.getUsers().forEach(System.out::println);
		//				byte[] tests = openPGP.encryptMessage("test", UUID.fromString("1ba79114-df4d-4838-a09e-108869dc1017"), EncryptionAlgorithm.TDESWithEDE);
		//				String s = openPGP.decryptMessage(tests, EncryptionAlgorithm.TDESWithEDE);
		//				System.out.println(s);

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		UUID id = UUID.fromString("aeec0789-40c4-4b2e-86c2-4943bbff198e");
		byte[] encrypt = openPGP.testEncrypt(id, "testtest123".getBytes());
		flushToFile(encrypt, "a.txt");
		byte[] bytes = openPGP.testDecrypt(id, encrypt);
		System.out.println(new String(bytes));
	}
}