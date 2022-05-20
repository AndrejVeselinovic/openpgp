package main.repositories;

import main.UserInfo;

import java.security.KeyPair;
import java.util.List;
import java.util.UUID;

public interface Repository {
	void persistKeyPair(String username, String email, String password, KeyPair keyPair);
	List<UserInfo> getUsers();
	boolean checkPassword(String username, String password);
	void deleteKeyPair(UUID keyId);

	void persistSessionKey(UUID sessionId, int keyIndex, byte[] key);

	byte[] retrieveSessionKey(UUID sessionId, int keyIndex);

	void deleteSessionKey(UUID sessionId);
}
