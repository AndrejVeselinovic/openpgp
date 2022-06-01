package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import lombok.Getter;
import main.dtos.KeyType;
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

	@Getter
	private final KeyType keyType;
	@Override
	public PGPKeyPair generateKeyPair(int size) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL");
			keyPairGenerator.initialize(size);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, keyPair, new Date());
		} catch (NoSuchAlgorithmException | PGPException e) {
			throw new RuntimeException(e);
		}
	}
}
