package main.algorithms.asymmetric;

import lombok.AllArgsConstructor;
import lombok.Getter;
import main.dtos.KeyType;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

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
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
//			keyPairGenerator.initialize(new ElGamalParameterSpec(P, Q));
			keyPairGenerator.initialize(3072);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, keyPair, new Date());
		} catch (NoSuchAlgorithmException | PGPException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

//	@Override
//	public PGPKeyPair generateKeyPair(int size) {
//		ElGamalKeyPairGenerator elGamalKeyPairGenerator = new ElGamalKeyPairGenerator();
////		elGamalKeyPairGenerator.init(new KeyGenerationParameters(new SecureRandom(), size));
//		elGamalKeyPairGenerator.init(new ElGamalKeyGenerationParameters(new SecureRandom(), new ElGamalParameters(P, Q)));
//		AsymmetricCipherKeyPair elgKp = elGamalKeyPairGenerator.generateKeyPair();
//		try {
//			return new BcPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
//		} catch (PGPException e) {
//			throw new RuntimeException(e);
//		}
//	}
}

