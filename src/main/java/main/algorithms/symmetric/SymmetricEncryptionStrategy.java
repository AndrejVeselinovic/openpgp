package main.algorithms.symmetric;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

public abstract class SymmetricEncryptionStrategy {
	public byte[] encrypt(byte[] data, PGPPublicKey publicKey, boolean shouldCompress, PGPPrivateKey signingKey) throws IOException, PGPException {
//		data = PGPSign.test(data, signingKey);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		ArmoredOutputStream aos = new ArmoredOutputStream(bos);

		byte[] compressedData = compress(data, shouldCompress, signingKey);
		OutputStream encOut = getEncryptedGenerator(publicKey).open(aos, compressedData.length);

		encOut.write(compressedData);

		encOut.close();

		aos.close();

		byte[] bytes = bos.toByteArray();
		bos.close();
		return bytes;
	}

	private PGPEncryptedDataGenerator getEncryptedGenerator(PGPPublicKey publicKey) {
		int symmetricKeyAlgorithmTag = getSymmetricKeyAlgorithmTag();
		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithmTag).setWithIntegrityPacket(true)
						.setSecureRandom(new SecureRandom())
						.setProvider("BC"));

		encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

		return encGen;
	}

	private byte[] compress(byte[] data, boolean shouldCompress, PGPPrivateKey signingKey)
			throws IOException, PGPException {
		int compressionAlgorithmTag = CompressionAlgorithmTags.UNCOMPRESSED;
		if(shouldCompress) {
			compressionAlgorithmTag = CompressionAlgorithmTags.ZIP;
		}
		PGPCompressedDataGenerator compressGen = new PGPCompressedDataGenerator(compressionAlgorithmTag);

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		OutputStream compressOut = compressGen.open(bos);

//		PGPSignatureGenerator signGen = PGPSign.getSignatureGenerator(signingKey, bos);

		PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
		OutputStream os = literalGen.open(compressOut, PGPLiteralData.BINARY,
				PGPLiteralDataGenerator.CONSOLE, data.length, new Date());

//		signGen.update(data);
		os.write(data);

//		signGen.generate().encode(compressOut);

		compressOut.close();
		os.close();
		compressGen.close();
		literalGen.close();

		return bos.toByteArray();
	}

	private byte[] compressSafeCopy(byte[] data, boolean shouldCompress) throws IOException {
		int compressionAlgorithmTag = CompressionAlgorithmTags.UNCOMPRESSED;
		if(shouldCompress) {
			compressionAlgorithmTag = CompressionAlgorithmTags.ZIP;
		}
		PGPCompressedDataGenerator compressGen = new PGPCompressedDataGenerator(compressionAlgorithmTag);

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		OutputStream compressOut = compressGen.open(bos);

		OutputStream os = new PGPLiteralDataGenerator().open(compressOut, PGPLiteralData.BINARY,
				PGPLiteralDataGenerator.CONSOLE, data.length, new Date());

		os.write(data);

		os.close();

		compressGen.close();

		return bos.toByteArray();
	}

	abstract int getSymmetricKeyAlgorithmTag();
}
