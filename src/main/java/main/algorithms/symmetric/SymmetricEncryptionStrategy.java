package main.algorithms.symmetric;

import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

public interface SymmetricEncryptionStrategy {
	default byte[] encryptMessage(byte[] data, PGPPublicKey encryptionKey) {
		int symmetricKeyAlgorithmTag = getSymmetricKeyAlgorithmTag();
		try {
			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithmTag).setWithIntegrityPacket(true)
							.setSecureRandom(new SecureRandom())
							.setProvider("BC"));
			encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));
			ByteArrayOutputStream encOut = new ByteArrayOutputStream();
			// create an indefinite length encrypted stream
			OutputStream cOut = encGen.open(encOut, new byte[4096]);
			// write out the literal data
			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			OutputStream pOut = lData.open(cOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length,
					new Date());
			pOut.write(data);
			pOut.close();
			// finish the encryption
			cOut.close();
			return encOut.toByteArray();
		} catch (PGPException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	int getSymmetricKeyAlgorithmTag();
}
