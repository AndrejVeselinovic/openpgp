package main;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;

@AllArgsConstructor
public class SecretKeyInfo {
	@Getter
	private PGPSecretKey secretKey;
	@Getter
	private KeyType keyType;

}
