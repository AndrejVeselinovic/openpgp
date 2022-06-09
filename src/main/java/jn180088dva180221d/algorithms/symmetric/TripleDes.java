package jn180088dva180221d.algorithms.symmetric;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

public class TripleDes extends SymmetricEncryptionStrategy {

	@Override
	public int getSymmetricKeyAlgorithmTag() {
		return SymmetricKeyAlgorithmTags.TRIPLE_DES;
	}
}
