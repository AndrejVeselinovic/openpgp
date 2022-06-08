package main.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.openpgp.PGPSecretKey;

@AllArgsConstructor
public class SecretKeyInfo {
	@Getter
	private PGPSecretKey secretKey;
	@Getter
	private String keyType;

}
