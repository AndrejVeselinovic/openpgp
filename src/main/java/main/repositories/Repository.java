package main.repositories;

import main.SecretKeyInfo;
import main.PublicKeyInfo;
import main.UserKeyInfo;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

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

	PublicKeyInfo retrievePublicEncryptionKey(UUID keyId);

	SecretKeyInfo retrievePrivateEncryptionKey(UUID keyId);

	public byte[] retrievePublicKey(UUID keyId);
}
