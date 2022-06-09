package jn180088dva180221d.dtos;

public class SymmetricAlgorithmTagsConverter {

	public static String of(int tag) {
		switch (tag) {
		case 1:
			return "RSA_GENERAL";
		case 2:
			return "RSA_ENCRYPT";
		case 3:
			return "RSA_SIGN";
		case 16:
			return "ELGAMAL_ENCRYPT";
		case 17:
			return "DSA";
		case 18:
			return "ECDH";
		case 19:
			return "ECDSA";
		case 20:
			return "ELGAMAL_GENERAL";
		case 21:
			return "DIFFIE_HELLMAN";
		case 22:
			return "EDDSA";
		default:
			return "UNKNOWN";
		}
	}

}
