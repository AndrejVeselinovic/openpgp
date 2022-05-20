package main.repositories;

import main.KeyInfo;
import main.KeyType;
import main.UserKeyInfo;

import java.io.*;
import java.security.KeyPair;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class FileRepository implements Repository {
	private static final String KEY_RING_DIRECTORY = "keys/";
	private static final String USERS_FILE = KEY_RING_DIRECTORY + "users.csv";
	private static final String PRIVATE_KEY_EXTENSION = ".priv";
	private static final String PUBLIC_KEY_EXTENSION = ".pub";
	private static final String SESSIONS_DIRECTORY = "sessions/";

	static {
		File usersFile = new File(USERS_FILE);
		try {
			usersFile.createNewFile();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void persistKeyPair(String username, String email, String password, KeyPair keyPair, KeyType keyType) {
		UUID keyId = UUID.randomUUID();
		File usersFile = new File(USERS_FILE);
		File privateKeyFile = new File(KEY_RING_DIRECTORY + keyId + PRIVATE_KEY_EXTENSION);
		File publicKeyFile = new File(KEY_RING_DIRECTORY + keyId + PUBLIC_KEY_EXTENSION);
		try {
			privateKeyFile.createNewFile();
			publicKeyFile.createNewFile();
			try (FileOutputStream usersOutput = new FileOutputStream(usersFile, true);
					FileOutputStream privateOutput = new FileOutputStream(privateKeyFile);
					FileOutputStream publicOutput = new FileOutputStream(publicKeyFile)) {
				privateOutput.write(keyPair.getPrivate().getEncoded());
				publicOutput.write(keyPair.getPublic().getEncoded());
				String usersWrite = String.format("%s,%s,%s,%s,%s\n", username, email,
						password, keyId, keyType);
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
					.anyMatch(userInfo -> userInfo.getUsername().equals(username) && userInfo.getPassword().equals(password));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void deleteKeyPair(UUID keyId) {
		File privateKeyFile = new File(KEY_RING_DIRECTORY + keyId + PRIVATE_KEY_EXTENSION);
		File publicKeyFile = new File(KEY_RING_DIRECTORY + keyId + PUBLIC_KEY_EXTENSION);
		if(!privateKeyFile.delete()) {
			throw new RuntimeException("Error deleting private key file for key " + keyId);
		}

		if(!publicKeyFile.delete()) {
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

		try(FileOutputStream fileOutputStream = new FileOutputStream(file)) {
			fileOutputStream.write(key);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] retrieveSessionKey(UUID sessionId, int keyIndex) {
		String path = String.format("%s%s/%s", SESSIONS_DIRECTORY, sessionId, keyIndex);
		File file = new File(path);

		try(FileInputStream fileInputStream = new FileInputStream(file)) {
			return fileInputStream.readAllBytes();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void deleteSessionKey(UUID sessionId) {
		deleteDirectory(new File(SESSIONS_DIRECTORY + sessionId));
	}

	private KeyInfo retrieveKey(UUID keyId, String extensionType) {
		byte[] bytes;
		KeyType keyType = null;

		try(FileInputStream fileInputStream = new FileInputStream(KEY_RING_DIRECTORY + keyId + extensionType)){
			bytes = fileInputStream.readAllBytes();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		try(BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))){
			List<String> lines = bufferedReader.lines().collect(Collectors.toList());
			for(String line: lines){
				String[] args = line.split(",");
				if(args[3].equals(keyId.toString())) {
					keyType = KeyType.valueOf(args[4]);
					break;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		if(keyType == null) {
			throw new RuntimeException("couldnt find public key with key id: " + keyId);
		}
		return new KeyInfo(bytes, keyType);
	}
	@Override
	public KeyInfo retrievePublicKey(UUID keyId) {
		return retrieveKey(keyId, PUBLIC_KEY_EXTENSION);
	}

	@Override
	public KeyInfo retrievePrivateKey(UUID keyId) {
		return retrieveKey(keyId, PRIVATE_KEY_EXTENSION);
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
		try (
				BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE));
				BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(tempFileName))
		) {
			while(true) {
				String line = bufferedReader.readLine();
				if(line == null) {
					break;
				}
				UserKeyInfo userInfo = fromLine(line);
				if(userInfo.getKeyId().equals(keyId)) {
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
		if (args.length != 5) {
			throw new RuntimeException("Error parsing user from file, line: " + line);
		}

		return new UserKeyInfo(args[0], args[1], args[2], UUID.fromString(args[3]), KeyType.valueOf(args[4]));
	}
}
