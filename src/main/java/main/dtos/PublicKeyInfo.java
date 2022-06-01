package main.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.openpgp.PGPPublicKey;

@AllArgsConstructor
public class PublicKeyInfo {
	@Getter
	private PGPPublicKey publicKey;
	@Getter
	private KeyType keyType;

}
