package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import main.dtos.SymmetricAlgorithmTagsConverter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Date;

@AllArgsConstructor
public class ElGamalStrategy implements AsymmetricStrategy {
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private static final int algorithmTag = PGPPublicKey.ELGAMAL_ENCRYPT;
	@Override
	public PGPKeyPair generateKeyPair(int size) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL");
			keyPairGenerator.initialize(size);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return new JcaPGPKeyPair(algorithmTag, keyPair, new Date());
		} catch (NoSuchAlgorithmException | PGPException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String getKeyType() {
		return SymmetricAlgorithmTagsConverter.of(algorithmTag);
	}
}
