package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import lombok.Getter;
import main.KeyType;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

@AllArgsConstructor
public class DSAStrategy implements AsymmetricStrategy {

	@Getter
	private final KeyType keyType;
	@Override
	public PGPKeyPair generateKeyPair(int size) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
			generator.initialize(size);
			KeyPair keyPair = generator.generateKeyPair();
			return new JcaPGPKeyPair(PGPPublicKey.DSA, keyPair, new Date());
		} catch (NoSuchAlgorithmException | PGPException e) {
			throw new RuntimeException(e);
		}
	}
}
