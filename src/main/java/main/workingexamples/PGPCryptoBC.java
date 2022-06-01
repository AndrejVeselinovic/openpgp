package main.workingexamples;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;

public class PGPCryptoBC {

	public PGPCryptoBC() {
		try {
//			String keysDir = System.getProperty("user.dir")+File.separator+"src/george/crypto/pgp/keys";

			//Generating a safe prime is a very long process so it's better to use
			//a pre-generated safe prime, I took this from http://www.cryptopp.com/fom-serve/cache/71.html
			BigInteger primeModulous = new BigInteger("36F0255DDE973DCB3B399D747F23E32ED6FDB1F77598338BFDF44159C4EC64DDAEB5F78671CBFB22106AE64C32C5BCE4CFD4F5920DA0EBC8B01ECA9292AE3DBA1B7A4A899DA181390BB3BD1659C81294F400A3490BF9481211C79404A576605A5160DBEE83B4E019B6D799AE131BA4C23DFF83475E9C40FA6725B7C9E3AA2C6596E9C05702DB30A07C9AA2DC235C5269E39D0CA9DF7AAD44612AD6F88F69699298F3CAB1B54367FB0E8B93F735E7DE83CD6FA1B9D1C931C41C6188D3E7F179FC64D87C5D13F85D704A3AA20F90B3AD3621D434096AA7E8E7C66AB683156A951AEA2DD9E76705FAEFEA8D71A5755355970000000000000001", 16);
			BigInteger baseGenerator = new BigInteger("2", 16);
			ElGamalParameterSpec paramSpecs = new ElGamalParameterSpec(primeModulous, baseGenerator);

			KeyPair dsaKeyPair = PGPTools.generateDsaKeyPair(1024);
			KeyPair elGamalKeyPair = PGPTools.generateElGamalKeyPair(paramSpecs);
			PGPKeyRingGenerator pgpKeyRingGen = PGPTools.createPGPKeyRingGenerator(dsaKeyPair, "test@gmail.com", "TestPass12345!".toCharArray());

			PGPTools.exportSecretKey(pgpKeyRingGen, new File("secret.asc"), true);
			PGPTools.exportPublicKey(pgpKeyRingGen, new File("public.asc"), true);
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void main(String ... args) {
		new PGPCryptoBC();
	}
}