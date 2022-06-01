package main.algorithms.symmetric;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.InputStream;

public class DecryptionAlgorithm {

	public static byte[] decrypt(byte[] pgpEncryptedData, PGPPrivateKey privateKey) {
		try {
			PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);
			PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
			// find the matching public key encrypted data packet.
			PGPPublicKeyEncryptedData encData = null;
			for (PGPEncryptedData pgpEnc : encList) {
				PGPPublicKeyEncryptedData pkEnc = (PGPPublicKeyEncryptedData) pgpEnc;
				if (pkEnc.getKeyID() == privateKey.getKeyID()) {
					encData = pkEnc;
					break;
				}
			}
			if (encData == null) {
				throw new IllegalStateException("matching encrypted data not found");
			}
			// build decryptor factory
			PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(
					"BC").build(privateKey);
			InputStream clear = encData.getDataStream(dataDecryptorFactory);
			byte[] literalData = Streams.readAll(clear);
			clear.close();
			// check data decrypts okay
			if (encData.verify()) {
				// parse out literal data
				PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
				PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
				byte[] data = Streams.readAll(litData.getInputStream());
				return data;
			}
			throw new IllegalStateException("modification check failed");
		} catch (PGPException | IOException e) {
			throw new RuntimeException(e);
		}
	}
}
