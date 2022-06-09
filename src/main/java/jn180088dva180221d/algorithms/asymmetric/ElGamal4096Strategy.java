package jn180088dva180221d.algorithms.asymmetric;

import jn180088dva180221d.dtos.SymmetricAlgorithmTagsConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

public class ElGamal4096Strategy implements AsymmetricStrategy {
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	ElGamalKeyGenerationParameters param;
	ElGamalKeyPairGenerator engine = new ElGamalKeyPairGenerator();
	SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
	boolean initialised;

	public ElGamal4096Strategy() {
	}

	@Override
	public PGPKeyPair generateKeyPair(int size) {
		if (!initialised)
		{
			ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

			pGen.init(size, 0, new SecureRandom());
			param = new ElGamalKeyGenerationParameters(random, pGen.generateParameters());

			engine.init(param);
			initialised = true;
		}

		AsymmetricCipherKeyPair pair = engine.generateKeyPair();
		try {
			return new BcPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, pair, new Date());
		} catch (PGPException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String getKeyType() {
		return SymmetricAlgorithmTagsConverter.of(PGPPublicKey.ELGAMAL_ENCRYPT);
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

