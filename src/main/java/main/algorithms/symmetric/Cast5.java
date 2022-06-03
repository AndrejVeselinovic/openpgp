package main.algorithms.symmetric;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

public class Cast5 implements SymmetricEncryptionStrategy{
	@Override
	public int getSymmetricKeyAlgorithmTag() {
		return SymmetricKeyAlgorithmTags.CAST5;
	}
}
