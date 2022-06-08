package main.repositories;

import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.dtos.UserKeyInfo;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
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

	void persistPublicKey(PGPPublicKey signingKey, PGPPublicKey encryptionKey, byte[] bytesToWrite, UUID keyUUID) throws IOException;

	void persistSecretKey(PGPSecretKey signingKey, PGPSecretKey encryptionKey, byte[] secretKeyBytes, UUID keyUUID, String password) throws IOException;

	Optional<UserKeyInfo> getUserKeyInfoByLongKeyID(long keyId);
}
