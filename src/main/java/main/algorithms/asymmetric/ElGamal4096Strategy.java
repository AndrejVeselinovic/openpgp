package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import lombok.Getter;
import main.KeyType;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPKeyPair;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

@AllArgsConstructor
public class ElGamal4096Strategy implements AsymmetricStrategy {
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	@Getter
	private final KeyType keyType;

	private static final BigInteger P = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
	private static final BigInteger Q = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);

	@Override
	public PGPKeyPair generateKeyPair(int size) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL");
			keyPairGenerator.initialize(new ElGamalParameterSpec(P, Q));
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return null;
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}
}

