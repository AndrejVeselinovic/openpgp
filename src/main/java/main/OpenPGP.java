package main;

import lombok.AllArgsConstructor;
import main.algorithms.asymmetric.KeyPairAlgorithm;
import main.algorithms.symmetric.EncryptionAlgorithm;
import main.dtos.DecryptionInfo;
import main.dtos.UserKeyInfo;
import main.repositories.FileRepository;
import main.repositories.Repository;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@AllArgsConstructor
public class OpenPGP {
	private final Repository repository;

	private PGPKeyRingGenerator createPGPKeyRingGenerator(PGPKeyPair dsaKeyPair, PGPKeyPair elGamalKeyPair,
			String email) {
		try {
			PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build()
					.get(HashAlgorithmTags.SHA1);
			PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
					PGPSignature.POSITIVE_CERTIFICATION,
					dsaKeyPair,
					email,
					sha1Calc,
					null,
					null,
					new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
					null
			);
			keyRingGen.addSubKey(elGamalKeyPair);
			return keyRingGen;
		} catch (PGPException e) {
			throw new RuntimeException(e);
		}
	}

	public void generateKeyPair(String username, String email, String password, KeyPairAlgorithm dsaAlgorithm,
			KeyPairAlgorithm elGamalAlgorithm) {
		PGPKeyPair dsaKeyPair = dsaAlgorithm.generateKeyPair();
		PGPPublicKey publicKey = dsaKeyPair.getPublicKey();
		long keyID = publicKey.getKeyID();
		PGPPrivateKey privateKey = dsaKeyPair.getPrivateKey();
		long keyID1 = privateKey.getKeyID();
		PGPKeyPair elGamalKeyPair = elGamalAlgorithm.generateKeyPair();
		PGPKeyRingGenerator pgpKeyRingGenerator = createPGPKeyRingGenerator(dsaKeyPair, elGamalKeyPair, email);
		UUID keyId = repository.persistKeyPair(pgpKeyRingGenerator);
		UserKeyInfo userKeyInfo = new UserKeyInfo(username, password, email, keyId, dsaAlgorithm.getKeyType(),
				elGamalAlgorithm.getKeyType(), true, true, dsaKeyPair.getKeyID());
		repository.persistUserKeyInfo(userKeyInfo);
	}

	public String getPasswordForKeyId(UUID keyId){
		return repository.getPasswordForKeyId(keyId);
	}

	public List<UserKeyInfo> getUserKeys() {
		return repository.getUsers();
	}

	public void deleteKeyPair(UUID keyId) throws IOException {
		repository.deleteKeyPair(keyId);
	}

	public byte[] encrypt(
			String message,
			Collection<UUID> publicKeyUuids,
			EncryptionAlgorithm encryptionAlgorithm,
			boolean shouldCompress,
			UUID keyToSignMessageWith,
			String signingKeyPassword,
			boolean shouldEncode
	) throws PGPException, GeneralSecurityException, IOException {
		return encryptionAlgorithm.encryptMessage(message, publicKeyUuids, shouldCompress,
					keyToSignMessageWith, signingKeyPassword, shouldEncode);
	}

	public DecryptionInfo decrypt(byte[] message, String password, UUID privateKeyUuid) throws PGPException, IOException {
		return EncryptionAlgorithm.decryptMessage(message, password, privateKeyUuid);
	}

	public static void flushToFile(byte[] bytes) {
		flushToFile(bytes, "test.txt");
	}


	public static void flushToFile(byte[] bytes, String filename) {
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

	public void exportKeyPair(UUID keyId, String newPath) throws IOException {
		this.repository.exportKeyPair(keyId, newPath);
	}

	public void importPublicKey(File inputFile) throws PGPException, IOException {
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		ArmoredInputStream armoredInputStream = new ArmoredInputStream(fileInputStream);
		InputStream in = new ByteArrayInputStream(armoredInputStream.readAllBytes());
		in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

		JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);
		in.close();

		PGPPublicKey signingKey = null;
		PGPPublicKey encryptionKey = null;
		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
		outerWhile: while (signingKey == null && rIt.hasNext())
		{
			PGPPublicKeyRing kRing = rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
			while (kIt.hasNext())
			{
				PGPPublicKey key = kIt.next();

				if(key.isMasterKey()) {
					signingKey = key;
					continue;
				}

				if (key.isEncryptionKey())
				{
					encryptionKey = key;
					break outerWhile;
				}
			}
		}
		fileInputStream.close();
		if(signingKey == null || encryptionKey == null) {
			throw new RuntimeException("Error while importing public key: couldnt find signing or encryption key");
		}

		long keyID = signingKey.getKeyID();
		UUID keyUUID;
		Optional<UserKeyInfo> userKeyInfoByLongKeyID = repository.getUserKeyInfoByLongKeyID(keyID);
		if(userKeyInfoByLongKeyID.isPresent()) {
			keyUUID = userKeyInfoByLongKeyID.get().getKeyId();
		} else {
			keyUUID = UUID.randomUUID();
		}
		repository.persistPublicKey(signingKey, encryptionKey, pgpPub.getEncoded(), keyUUID);
	}

	public void importSecretKey(File inputFile, String password) throws PGPException, IOException, RuntimeException {
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		ArmoredInputStream armoredInputStream = new ArmoredInputStream(fileInputStream);
		InputStream in = new ByteArrayInputStream(armoredInputStream.readAllBytes());
		in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

		JcaPGPSecretKeyRingCollection pgpSecret = new JcaPGPSecretKeyRingCollection(in);
		in.close();

		PGPSecretKey signingKey = null;
		PGPSecretKey encryptionKey = null;
		Iterator<PGPSecretKeyRing> rIt = pgpSecret.getKeyRings();
		outerWhile: while (signingKey == null && rIt.hasNext())
		{
			PGPSecretKeyRing kRing = rIt.next();
			Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();
			while (kIt.hasNext())
			{
				PGPSecretKey key = kIt.next();

				if(key.isMasterKey()) {
					signingKey = key;
				} else {
					encryptionKey = key;
					break outerWhile;
				}
			}
		}
		fileInputStream.close();
		if(signingKey == null || encryptionKey == null) {
			throw new RuntimeException("Error while importing secret key: couldnt find signing or encryption key");
		}

		try{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			signingKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
							.build(password.toCharArray()));
		} catch (PGPException e) {
			throw new RuntimeException("Invalid Password!");
		}

		long keyID = signingKey.getKeyID();
		UUID keyUUID;
		Optional<UserKeyInfo> userKeyInfoByLongKeyID = repository.getUserKeyInfoByLongKeyID(keyID);
		if(userKeyInfoByLongKeyID.isPresent()) {
			keyUUID = userKeyInfoByLongKeyID.get().getKeyId();
		} else {
			keyUUID = UUID.randomUUID();
		}
		repository.persistSecretKey(signingKey, encryptionKey, pgpSecret.getEncoded(), keyUUID, password);
	}

	public static void main(String[] args) throws Exception {
		OpenPGP openPGP = new OpenPGP(new FileRepository());

//		openPGP.generateKeyPair("andrej", "email@gmail.com", "123", KeyPairAlgorithm.DSA_1024, KeyPairAlgorithm.ElGamal4096);
//		openPGP.generateKeyPair("andrej", "email@gmail.com", "123", KeyPairAlgorithm.DSA_2048, KeyPairAlgorithm.ElGamal2048);
//		openPGP.getUserKeys().forEach(System.out::println);
//		openPGP.deleteKeyPair(UUID.fromString("44684ede-3545-4d09-b294-98802a073879"));
//		openPGP.getUserKeys().forEach(System.out::println);

//		String message = "test";
//		UUID keyPairUuid = UUID.fromString("57d58695-449c-4eb6-af53-2d5ef6734ee9");
//		UUID keyPairUuid2 = UUID.fromString("7186e147-74ae-4b77-950f-e1050ab46270");
//		String password = "123";
//		byte[] encryptedBytes = openPGP.encrypt(message, List.of(new UUID[] {keyPairUuid}), EncryptionAlgorithm.CAST5, false, keyPairUuid, password, false);
//		System.out.println("Successfully encrypted");
//		flushToFile(encryptedBytes, "message.txt");
//		DecryptionInfo decryptedString = openPGP.decrypt(encryptedBytes, password, keyPairUuid);
//		System.out.println("Successfully decrypted");
//		System.out.println(decryptedString.getMessage());
//
//		System.out.println(openPGP.repository.getPasswordForKeyId(
//				UUID.fromString("adaaa6fc-d1ea-46da-9a7c-145dd9c48731")));
		openPGP.importPublicKey(new File("test.priv.asc"));
//		openPGP.importSecretKey(new File("test.priv.asc"), "123");
	}
}