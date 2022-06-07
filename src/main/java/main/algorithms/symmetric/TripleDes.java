package main.algorithms.symmetric;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import java.security.Security;

public class TripleDes extends SymmetricEncryptionStrategy {

	@Override
	public int getSymmetricKeyAlgorithmTag() {
		return SymmetricKeyAlgorithmTags.TRIPLE_DES;
	}
}
