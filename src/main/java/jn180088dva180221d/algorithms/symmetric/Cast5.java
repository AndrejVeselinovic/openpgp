package jn180088dva180221d.algorithms.symmetric;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

public class Cast5 extends SymmetricEncryptionStrategy{
	@Override
	public int getSymmetricKeyAlgorithmTag() {
		return SymmetricKeyAlgorithmTags.CAST5;
	}
}
