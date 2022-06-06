package main.utils;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPDataValidationException;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.rmi.server.ExportException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class PGPDecrypt {

	private PGPDecrypt() {
		throw new IllegalAccessError("Utility class");
	}

	public static byte[] decrypt(byte[] encData, PGPPrivateKey privateKey) throws IOException {
		Collection<PGPPublicKeyEncryptedData> pgpEncryptedDataBlocks = getPGPEncryptedData(encData);

		for(PGPPublicKeyEncryptedData pgpEncData: pgpEncryptedDataBlocks) {
			try{
				InputStream is = getInputStream(privateKey, pgpEncData);

				// IMPORTANT: pipe() should be before verify(). Otherwise we get "java.io.EOFException: Unexpected end of ZIP
				// input stream".
				byte[] data = pipe(is);

				if (!pgpEncData.verify()) {
					throw new PGPDataValidationException("Data integrity check failed");
				}

				return data;
			} catch (Exception ignored) {}
		}
		throw new RuntimeException("Tried to decrypt with wrong private key");
	}

	private static byte[] pipe(InputStream is) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		Streams.pipeAll(is, bos);

		bos.close();

		return bos.toByteArray();
	}

	private static InputStream getInputStream(PGPPrivateKey privateKey, PGPPublicKeyEncryptedData pgpEncData)
			throws PGPException, IOException {

		PublicKeyDataDecryptorFactory bc = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);
		InputStream is = pgpEncData.getDataStream(bc);

		JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(is);

		Object message = objectFactory.nextObject();

		PGPCompressedData compressedData = (PGPCompressedData) message;

		JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());

		PGPLiteralData literalData = (PGPLiteralData) pgpObjectFactory.nextObject();

		return literalData.getInputStream();
	}

	private static Collection<PGPPublicKeyEncryptedData> getPGPEncryptedData(byte[] data) throws IOException {
		InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(data));

		JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(in);

		PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();

		Iterator<PGPEncryptedData> it = encryptedDataList.getEncryptedDataObjects();

		List<PGPPublicKeyEncryptedData> encryptedDataBlocks = new ArrayList<>();
		while(it.hasNext()) {
			encryptedDataBlocks.add((PGPPublicKeyEncryptedData) it.next());
		}
		return encryptedDataBlocks;
	}
}