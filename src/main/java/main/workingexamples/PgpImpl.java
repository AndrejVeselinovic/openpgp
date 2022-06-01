package main.workingexamples;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

public class PgpImpl {

	public PgpImpl() {
	}

	public static byte[] encrypt(byte[] data, PGPPublicKey encryptionKey) {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		String step = "Step-0";
		try {
			step = "Step-1";
			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES)
							.setWithIntegrityPacket(true)
							.setSecureRandom(new SecureRandom())
							.setProvider(provider));

			step = "Step-2";
			encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
					.setSecureRandom(new SecureRandom()).setProvider(provider));

			step = "Step-3";
			ByteArrayOutputStream encOut = new ByteArrayOutputStream();

			step = "Step-4";
			// create an indefinite length encrypted stream
			OutputStream cOut = encGen.open(encOut, new byte[1 << 16]);
			step = "Step-5";
			// write out the literal data
			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			OutputStream pOut = lData.open(cOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length,
					new Date());
			pOut.write(data);
			pOut.close();
			// finish the encryption
			cOut.close();
			step = "Step-6";

			return encOut.toByteArray();
		} catch (Exception e) {
			//throw new Exception(String.format("%s: %s", e.getMessage(), step));
			e.printStackTrace();
		}
		return null;
	}

	public static PGPPublicKey getPublicKey(String keyAscii) throws IOException, PGPException, Exception {
		InputStream encodedKey = new ByteArrayInputStream(keyAscii.getBytes());
		InputStream decodedKey = PGPUtil.getDecoderStream(encodedKey);

		JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(decodedKey);
		decodedKey.close();

		PGPPublicKey key = null;
		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();

			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = kIt.next();

				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}
		if (key == null) {
			throw new Exception("Can't find key");
		}
		return key;
	}

	public static void main(String[] args) {
		String publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n" + "Version: GnuPG v2.0.22 (GNU/Linux)\r\n"
				+ "\r\n" + "mQENBGA1A70BCADK8BnH6GgMbnS1TJSpJvgH+D9VIw0sN8XZWQsUmWWV9WSqhqXt\r\n"
				+ "5wNC4XJDcaWtMCapaekQXV5S52T7QCxAz/E5oZzIDe+IUCHQz0WUs37S4Wnw+SZ6\r\n"
				+ "QNPXOFaC4nNByRq6gvg0+wtD2Bo/3OJur3f0O0aRSHNiwfd0PdFgG0NU5vGV9PwE\r\n"
				+ "xbTMpGssWexIC0MwJaYfJkxzov33CkwLaITvBTCn/J3oeX6JarMkgpurp1FAW0Jk\r\n"
				+ "YzgGMOOxwuEVedwP4NtEPce+UtLv2NHHfqsW6xSxjWqsJkMdJ9afzu1jvn9M6e0j\r\n"
				+ "MOTmPUCYVCioXK59It8ngN8NLtwaPgfnBwcbABEBAAG0BWFsbGVuiQE5BBMBAgAj\r\n"
				+ "BQJgNQO9AhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQxzGJxIrjAlxq\r\n"
				+ "aggAgoiO82MZZMHyhZ3uLD4qTQ2vsT6+onhCr83kw0eFNM5AH0r3xlVARXHaViWC\r\n"
				+ "SFutpb/34lrCTpJfLfKwdFU2bJP2SI3hAujtTg45UFklswu6GZaqQno6JKkZM4hw\r\n"
				+ "ltFIXU1dMpIud7nsJ2QU46TI97n+HeD7DvOSGY/CFPnNot0YFHxXCKtHdPHk8JO3\r\n"
				+ "JdOG0X90Yi9XSI1USv8HL/WjOTvhSqo7Qps2MpcUZrfNsa0H9Adk9xVYiz0nKNPY\r\n"
				+ "qLQxFAiHb34vdav4e28anJ8th93SfiRn5OFK2G6R3DlhLlvn3h1dSAT6vSOrzx80\r\n"
				+ "EylyMg2BIbRfp+JEgwCMf2V8X7kBDQRgNQO9AQgA3qV0wYvdH5M4XBzVwDtuGuIs\r\n"
				+ "+GRcSRQqmvnt94e8ZE4Kv2w2Pf/JxPMwnPC92lVRypdOjmTZrT3R0z7g+D8mU5A9\r\n"
				+ "o/CPvvSShA8Jh3z69S+hLP0nSaajsVsQlBGrI8ehI1EVJDsNh15PZrl27OK0aBb4\r\n"
				+ "Fp0BYm0D2HaLnQPD4/jhTR13i1mt5E5hmBwiZiiWr/Wa1i1g1o/XaT4CApu91zgg\r\n"
				+ "cmJBz9DL/C2hYC5lkp/cz5IJYp5BsvfA2lwamca33aHxFj8+Bz3+REWa8zvEqQ9U\r\n"
				+ "a26RbPVjkeGChwNWLxNTuj1rNDdqB/KZO6iM02orqW86L45SKTBWYqPcpD7GeQAR\r\n"
				+ "AQABiQEfBBgBAgAJBQJgNQO9AhsMAAoJEMcxicSK4wJcOLEIAMevvOk9iZ13T3yA\r\n"
				+ "+ZW8mWKKE5aXy93VPKAvplP/WlW2VVGeb+6rEkFFsdN4doYIJPEIr+U7K0GDR6XX\r\n"
				+ "TKLyI7BtUZPegOdjgcFWVGFnFogDnkrO+IPY+JUy1VMg8fGStThfa2dYEgd7yqpq\r\n"
				+ "fZ97q5RQun1B+wyRdPDgC39roSGEwtXbRCZnuSMVNT7J9a2qnXkenvQRSoPjY7wQ\r\n"
				+ "tn1wUfnHyjyS9OzfXTSHDi2A5JDRCh5L/V7Q93/P5Isv/U4QzIWudGM6AjuaoZ6i\r\n"
				+ "chksRI9EchNKnSut9ebTyTkIJ80sB7Eyfp8TtORAnz8/Xf8A8aYD73r9rD4poSmo\r\n" + "FV15pP8=\r\n" + "=Yc74\r\n"
				+ "-----END PGP PUBLIC KEY BLOCK-----";

		try {
			PGPPublicKey key = getPublicKey(publicKey);
			System.out.println(encrypt("Test".getBytes(), key));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}