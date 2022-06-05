package main.repositories;

import main.dtos.KeyType;
import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.dtos.UserKeyInfo;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRing;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class FileRepository implements Repository {
	private static final String KEY_RING_DIRECTORY = "keys/";
	private static final String USERS_FILE = KEY_RING_DIRECTORY + "users.csv";
	private static final String PRIVATE_KEY_EXTENSION = ".priv";
	private static final String PUBLIC_KEY_EXTENSION = ".pub";
	private static final String KEY_EXTENSION = ".asc";
	private static final String SESSIONS_DIRECTORY = "sessions/";

	static {
		File keyRingDir = new File(KEY_RING_DIRECTORY);
		if (!keyRingDir.exists()){
			keyRingDir.mkdir();
		}

		File usersFile = new File(USERS_FILE);
		try {
			usersFile.createNewFile();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private String getPublicKeyFilePath(UUID keyId) {
		return KEY_RING_DIRECTORY + keyId + PUBLIC_KEY_EXTENSION + KEY_EXTENSION;
	}

	private String getPrivateKeyFilePath(UUID keyId) {
		return KEY_RING_DIRECTORY + keyId + PRIVATE_KEY_EXTENSION + KEY_EXTENSION;
	}

	@Override
	public UUID persistKeyPair(PGPKeyRingGenerator keyRingGenerator) {
		UUID keyId = UUID.randomUUID();
		File privateKeyFile = new File(getPrivateKeyFilePath(keyId));
		File publicKeyFile = new File(getPublicKeyFilePath(keyId));
		try {
			privateKeyFile.createNewFile();
			publicKeyFile.createNewFile();
			try (ArmoredOutputStream privateOutput = new ArmoredOutputStream(new FileOutputStream(privateKeyFile));
					ArmoredOutputStream publicOutput = new ArmoredOutputStream(new FileOutputStream(publicKeyFile))) {
				keyRingGenerator.generatePublicKeyRing().encode(publicOutput);
				keyRingGenerator.generateSecretKeyRing().encode(privateOutput);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return keyId;
	}

	@Override
	public void persistUserKeyInfo(UserKeyInfo userKeyInfo) {
		try {
			try (FileOutputStream usersOutput = new FileOutputStream(USERS_FILE, true)) {
				String usersWrite = String.format("%s,%s,%s,%s,%s,%s\n",
						userKeyInfo.getUsername(),
						userKeyInfo.getEmail(),
						userKeyInfo.getPassword(),
						userKeyInfo.getKeyId(),
						userKeyInfo.getEncryptionKeyType(),
						userKeyInfo.getSignatureKeyType());
				usersOutput.write(usersWrite.getBytes());
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public List<UserKeyInfo> getUsers() {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines().map(this::fromLine).collect(Collectors.toList());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean checkPassword(String username, String password) {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines()
					.map(this::fromLine)
					.anyMatch(userInfo -> userInfo.getUsername().equals(username) && userInfo.getPassword()
							.equals(password));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void deleteKeyPair(UUID keyId) {
		File privateKeyFile = new File(getPrivateKeyFilePath(keyId));
		File publicKeyFile = new File(getPublicKeyFilePath(keyId));
		if (!privateKeyFile.delete()) {
			throw new RuntimeException("Error deleting private key file for key " + keyId);
		}

		if (!publicKeyFile.delete()) {
			throw new RuntimeException("Error deleting public key file for key " + keyId);
		}

		deleteKeyRecord(keyId);
	}

	@Override
	public void persistSessionKey(UUID sessionId, int keyIndex, byte[] key) {
		String dirPath = String.format("%s%s/", SESSIONS_DIRECTORY, sessionId);
		File dir = new File(dirPath);
		dir.mkdirs();

		File file = new File(dirPath + keyIndex);

		try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
			fileOutputStream.write(key);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] retrieveSessionKey(UUID sessionId, int keyIndex) {
		String path = String.format("%s%s/%s", SESSIONS_DIRECTORY, sessionId, keyIndex);
		File file = new File(path);

		try (FileInputStream fileInputStream = new FileInputStream(file)) {
			return fileInputStream.readAllBytes();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void deleteSessionKey(UUID sessionId) {
		deleteDirectory(new File(SESSIONS_DIRECTORY + sessionId));
	}

	private PublicKeyInfo getPublicKey(UUID keyId, int keyType) {
		byte[] bytes;
		KeyType keyInfoType = null;
		PGPPublicKey encryptionKey;

		try (ArmoredInputStream inputStream = new ArmoredInputStream(new FileInputStream(getPublicKeyFilePath(keyId)))) {
			bytes = inputStream.readAllBytes();
			JcaPGPPublicKeyRing pgpPublicKeys = new JcaPGPPublicKeyRing(bytes);
			Iterator<PGPPublicKey> iterator = pgpPublicKeys.iterator();
			encryptionKey = iterator.next(); //signing key
			if(keyType == 2) {
				encryptionKey = iterator.next(); //encryption key
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			List<String> lines = bufferedReader.lines().collect(Collectors.toList());
			for (String line : lines) {
				String[] args = line.split(",");
				if (args[3].equals(keyId.toString())) {
					keyInfoType = KeyType.valueOf(args[4]);
					break;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		if (keyInfoType == null) {
			throw new RuntimeException("couldnt find public key with key id: " + keyId);
		}
		return new PublicKeyInfo(encryptionKey, keyInfoType);
	}

	private SecretKeyInfo getPrivateKey(UUID keyId, int keyType) {
		byte[] bytes;
		KeyType keyInfoType = null;
		PGPSecretKey encryptionKey;

		try (ArmoredInputStream fileInputStream = new ArmoredInputStream(new FileInputStream(getPrivateKeyFilePath(keyId)))) {
			bytes = fileInputStream.readAllBytes();
			fileInputStream.close();
			JcaPGPSecretKeyRing secretKeys = new JcaPGPSecretKeyRing(bytes);
			Iterator<PGPSecretKey> iterator = secretKeys.iterator();
			encryptionKey = iterator.next(); //signing key
			if(keyType == 2) {
				encryptionKey = iterator.next(); //encryption key
			}
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e);
		}

		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			List<String> lines = bufferedReader.lines().collect(Collectors.toList());
			for (String line : lines) {
				String[] args = line.split(",");
				if (args[3].equals(keyId.toString())) {
					keyInfoType = KeyType.valueOf(args[4]);
					break;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		if (keyInfoType == null) {
			throw new RuntimeException("couldnt find private key with key id: " + keyId);
		}
		return new SecretKeyInfo(encryptionKey, keyInfoType);
	}

	@Override
	public PublicKeyInfo getPublicEncryptionKey(UUID keyId) {
		return getPublicKey(keyId, 2);
	}

	@Override
	public PublicKeyInfo getPublicSigningKey(UUID keyId) {
		return getPublicKey(keyId, 1);
	}

	@Override
	public SecretKeyInfo getSecretEncryptionKey(UUID keyId) {
		return getPrivateKey(keyId, 2);
	}

	@Override
	public SecretKeyInfo getSecretSigningKey(UUID keyId) {
		return getPrivateKey(keyId, 1);
	}

	@Override
	public byte[] retrievePublicKey(UUID keyId) {
		try (ArmoredInputStream inputStream = new ArmoredInputStream(new FileInputStream(getPublicKeyFilePath(keyId)))){
			return inputStream.readAllBytes();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void deleteDirectory(File directoryToBeDeleted) {
		File[] allContents = directoryToBeDeleted.listFiles();
		if (allContents != null) {
			for (File file : allContents) {
				deleteDirectory(file);
			}
		}
		directoryToBeDeleted.delete();
	}

	private void deleteKeyRecord(UUID keyId) {
		String tempFileName = USERS_FILE + ".tmp";
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE));
				BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(tempFileName))) {
			while (true) {
				String line = bufferedReader.readLine();
				if (line == null) {
					break;
				}
				UserKeyInfo userInfo = fromLine(line);
				if (userInfo.getKeyId().equals(keyId)) {
					continue;
				}
				bufferedWriter.write(line);
			}

			File initialUsersFile = new File(USERS_FILE);
			initialUsersFile.delete();
			File newUsersFile = new File(tempFileName);
			newUsersFile.renameTo(initialUsersFile);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private UserKeyInfo fromLine(String line) {
		String[] args = line.split(",");
		if (args.length != 6) {
			throw new RuntimeException("Error parsing user from file, line: " + line);
		}

		return new UserKeyInfo(args[0], args[1], args[2], UUID.fromString(args[3]), KeyType.valueOf(args[4]), KeyType.valueOf(args[5]));
	}
}
