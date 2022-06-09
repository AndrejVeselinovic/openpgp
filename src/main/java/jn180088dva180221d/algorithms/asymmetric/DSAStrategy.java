package jn180088dva180221d.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import jn180088dva180221d.dtos.SymmetricAlgorithmTagsConverter;
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

	@Override
	public String getKeyType() {
		return SymmetricAlgorithmTagsConverter.of(PGPPublicKey.DSA);
	}
}
