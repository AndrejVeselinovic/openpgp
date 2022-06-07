package main.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.UUID;

@Getter
@ToString
@AllArgsConstructor
public class UserKeyInfo {
	private static final String DEFAULT_VALUE = "N/A";
	private String username = DEFAULT_VALUE;
	private String password = DEFAULT_VALUE;
	private String email = DEFAULT_VALUE;
	private UUID keyId;
	private KeyType signatureKeyType;
	private KeyType encryptionKeyType;

	public UserKeyInfo() {
		this.signatureKeyType = KeyType.UNKNOWN;
		this.encryptionKeyType = KeyType.UNKNOWN;
	}
}
