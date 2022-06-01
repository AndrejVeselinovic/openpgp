package main.workingexamples;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.TreeSet;

public final class PGPTools {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private PGPTools() {

	}

	public static final void exportSecretKey(PGPKeyRingGenerator pgpKeyRingGen, File keyFile, boolean asciiArmor)
			throws IOException {
		PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();

		if (asciiArmor) {
			ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(keyFile));
			pgpSecKeyRing.encode(armoredOutputStream);
			armoredOutputStream.close();
		} else {
			FileOutputStream fileOutputStream = new FileOutputStream(keyFile);
			pgpSecKeyRing.encode(fileOutputStream);
			fileOutputStream.close();
		}
	}

	public static final void exportPublicKey(PGPKeyRingGenerator pgpKeyRingGen, File keyFile, boolean asciiArmor)
			throws IOException {
		PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing();

		if (asciiArmor) {
			ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(keyFile));
			pgpPubKeyRing.encode(armoredOutputStream);
			armoredOutputStream.close();
		} else {
			FileOutputStream fileOutputStream = new FileOutputStream(keyFile);
			pgpPubKeyRing.encode(fileOutputStream);
			fileOutputStream.close();
		}
	}

	/**
	 * @param dsaKeyPair     - the generated DSA key pair
	 * @param identity       - the given identity of the key pair ring
	 * @param passphrase     - the secret pass phrase to protect the key pair
	 * @return a PGP Key Ring Generate with the El Gamal key pair added as sub key
	 * @throws Exception
	 */
	@SuppressWarnings("deprecation")
	public static final PGPKeyRingGenerator createPGPKeyRingGenerator(KeyPair dsaKeyPair,
			String identity, char[] passphrase) throws Exception {
		PGPKeyPair dsaPgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());
		PGPKeyPair elGamalPgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, dsaKeyPair, new Date());
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, elGamalPgpKeyPair,
				identity, sha1Calc, null, null,
				new JcaPGPContentSignerBuilder(elGamalPgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC")
						.build(passphrase));
		return keyRingGen;
	}

	/**
	 * @param keySize 512 - 1024 (multiple of 64)
	 * @return the DSA generated key pair
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */
	public static final KeyPair generateDsaKeyPair(int keySize)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
		keyPairGenerator.initialize(keySize);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	/**
	 * @param keySize - 1024, 2048, 4096
	 * @return the El Gamal generated key pair
	 * @throws Exception
	 */
	public static final KeyPair generateElGamalKeyPair(int keySize) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		keyPairGenerator.initialize(keySize);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	/**
	 * @param paramSpecs - the pre-defined parameter specs
	 * @return the El Gamal generated key pair
	 * @throws Exception
	 */
	public static final KeyPair generateElGamalKeyPair(ElGamalParameterSpec paramSpecs) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		keyPairGenerator.initialize(paramSpecs);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

}