package main.workingexamples;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Mac;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.util.Arrays;

public class HMAC_SHA1
{
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	private static int SHA1_SIGNATURE_LENGTH;

	public static byte[] generateSignature(byte[] secretKeyBytes, byte[] messageBytes) {
		HMac hMac = new HMac(new SHA1Digest());
		hMac.init(new KeyParameter(secretKeyBytes));
		hMac.update(messageBytes, 0, messageBytes.length);
		byte[] signatureBytes = new byte[hMac.getMacSize()];
		hMac.doFinal(signatureBytes, 0);
		return signatureBytes;
	}
	
	public static byte[] validateSignature(byte[] publicKeyBytes, byte[] signedMessageBytes)
			throws NoSuchProviderException {
		HMac hMac = new HMac(new SHA1Digest());
		SHA1_SIGNATURE_LENGTH = hMac.getMacSize();
		int messageLength = signedMessageBytes.length - SHA1_SIGNATURE_LENGTH;
		byte[] messageBytes = Arrays.copyOfRange(signedMessageBytes, 0, messageLength);
		byte[] oldSignatureBytes = Arrays.copyOfRange(signedMessageBytes, messageLength, signedMessageBytes.length);
		hMac.init(new KeyParameter(publicKeyBytes));
		hMac.update(messageBytes, 0, messageBytes.length);
		byte[] signatureBytes = new byte[SHA1_SIGNATURE_LENGTH];
		hMac.doFinal(signatureBytes, 0);
		if(!Arrays.equals(oldSignatureBytes, signatureBytes)) {
			throw new RuntimeException("CANNOT VALIDATE SIGNATURE");
		}
		return messageBytes;
	}

	public static void verifySignature(PublicKey dsaPublic, byte[] signedMessageBytes)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
//		byte[] messageBytes = Arrays.copyOf(signedMessageBytes, SHA1_SIGNATURE_LENGTH);
//		Signature signature = Signature.getInstance("SHA1WithDSA", "BC");
//		signature.initVerify(dsaPublic);
//		signature.update(messageBytes);
//		if(signature.verify(signedMessageBytes)){
//			throw new RuntimeException("CANNOT VALIDATE SIGNATURE");
//		}
		int messageLength = signedMessageBytes.length - SHA1_SIGNATURE_LENGTH;
		byte[] messageBytes = Arrays.copyOfRange(signedMessageBytes, 0, messageLength);
		byte[] oldSignatureBytes = Arrays.copyOfRange(signedMessageBytes, messageLength, signedMessageBytes.length);
		Mac sha1 = Mac.getInstance("Hmacsha1", "BC");
		sha1.init(dsaPublic);
		sha1.update(messageBytes);
		byte[] signatureBytes = sha1.doFinal();
		System.out.println(sha1.getMacLength());
		if(!Arrays.equals(oldSignatureBytes, signatureBytes)) {
			throw new RuntimeException("CANNOT VALIDATE SIGNATURE");
		}
	}


	public static byte[] generateSignature(PrivateKey dsaPrivate, byte[] input)
			throws GeneralSecurityException {
//		Signature signature = Signature.getInstance("SHA1WithDSA", "BC");
//		signature.initSign(dsaPrivate);
//		signature.update(input);
//		return signature.sign();
		Mac sha1 = Mac.getInstance("Hmacsha1", "BC");
		sha1.init(dsaPrivate);
		sha1.update(input);
		return sha1.doFinal();
	}
}