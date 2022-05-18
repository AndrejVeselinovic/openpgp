import algorithms.KeyPairAlgorithm;

public class OpenPGP {

	public void generateKeyPair(String username, String email, String password, KeyPairAlgorithm keyPairAlgorithm){
		keyPairAlgorithm.generateKeyPair();
	}

	public static void main(String[] args) {
		new OpenPGP().generateKeyPair(null, null, null, KeyPairAlgorithm.ElGamal1024);
	}
}