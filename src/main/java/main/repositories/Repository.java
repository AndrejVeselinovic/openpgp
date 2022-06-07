package main.repositories;

import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.dtos.UserKeyInfo;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

public interface Repository {
	UUID persistKeyPair(PGPKeyRingGenerator keyRingGenerator);
	void persistUserKeyInfo(UserKeyInfo userKeyInfo);
	List<UserKeyInfo> getUsers();
	boolean checkPassword(String username, String password);
	void deleteKeyPair(UUID keyId);

	void persistSessionKey(UUID sessionId, int keyIndex, byte[] key);

	byte[] retrieveSessionKey(UUID sessionId, int keyIndex);

	void deleteSessionKey(UUID sessionId);

	SecretKeyInfo getSecretEncryptionKey(UUID keyId);

	SecretKeyInfo getSecretSigningKey(UUID keyId);

	PublicKeyInfo getPublicEncryptionKey(UUID keyId);

	PublicKeyInfo getPublicSigningKey(UUID keyId);

	String getPasswordForKeyId(UUID keyId);

	byte[] retrievePublicKey(UUID keyId);

	UserKeyInfo getUserKeyInfo(UUID keyId);

	void exportKeyPair(UUID keyId, String newPath) throws IOException;
}
