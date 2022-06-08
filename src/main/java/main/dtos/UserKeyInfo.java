package main.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@AllArgsConstructor
public class UserKeyInfo {
	private static final String DEFAULT_VALUE = "N/A";

	private String username = DEFAULT_VALUE;
	@Setter
	private String password = DEFAULT_VALUE;
	private String email = DEFAULT_VALUE;
	private UUID keyId;
	private String signatureKeyType;
	private String encryptionKeyType;
	@Setter
	private boolean hasPublicKey;
	@Setter
	private boolean hasSecretKey;
	private long longKeyId;

	public UserKeyInfo() {
		this.signatureKeyType = SymmetricAlgorithmTagsConverter.of(-1);
		this.encryptionKeyType = SymmetricAlgorithmTagsConverter.of(-1);
	}

	@Override
	public String toString() {
		return String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
				this.getUsername(),
				this.getPassword(),
				this.getEmail(),
				this.getKeyId(),
				this.getSignatureKeyType(),
				this.getEncryptionKeyType(),
				this.hasPublicKey,
				this.hasSecretKey,
				this.longKeyId);
	}

	public static UserKeyInfo of(String line) {
		String[] args = line.split(",");
		if (args.length != 9) {
			throw new RuntimeException("Error parsing user from file, line: " + line);
		}

		return new UserKeyInfo(
				args[0],
				args[1],
				args[2],
				UUID.fromString(args[3]),
				args[4],
				args[5],
				args[6].equals("true"),
				args[7].equals("true"),
				Long.parseLong(args[8]));
	}
}
