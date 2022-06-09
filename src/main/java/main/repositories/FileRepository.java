package main.repositories;

import main.dtos.PublicKeyInfo;
import main.dtos.SecretKeyInfo;
import main.dtos.SymmetricAlgorithmTagsConverter;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
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
		try (FileWriter ignored = new FileWriter(USERS_FILE, true)) {
		} catch (IOException e) {
			e.printStackTrace();
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
		try {
			FileOutputStream outputStream = new FileOutputStream(getPrivateKeyFilePath(keyId));
			ArmoredOutputStream privateOutput = new ArmoredOutputStream(outputStream);

			FileOutputStream outputStream1 = new FileOutputStream(getPublicKeyFilePath(keyId));
			ArmoredOutputStream publicOutput = new ArmoredOutputStream(outputStream1);

			keyRingGenerator.generatePublicKeyRing().encode(publicOutput);
			keyRingGenerator.generateSecretKeyRing().encode(privateOutput);

			outputStream.close();
			outputStream1.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		return keyId;
	}

	@Override
	public void persistUserKeyInfo(UserKeyInfo userKeyInfo) {
		try {
			try (FileOutputStream usersOutput = new FileOutputStream(USERS_FILE, true)) {
				usersOutput.write(userKeyInfo.toString().getBytes());
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public List<UserKeyInfo> getUsers() {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines().filter(line->!line.equals("")).map(this::fromLine).collect(Collectors.toList());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean checkPassword(String username, String password) {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines()
					.filter(line -> !line.equals(""))
					.map(this::fromLine)
					.anyMatch(userInfo -> userInfo.getUsername().equals(username) && userInfo.getPassword()
							.equals(password));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void deleteKeyPair(UUID keyId) throws IOException {
		Path privateKeyPath = Path.of(getPrivateKeyFilePath(keyId));
		if(Files.exists(privateKeyPath)){
			Files.delete(privateKeyPath);
		}

		Path publicKeyPath = Path.of(getPublicKeyFilePath(keyId));
		if(Files.exists(publicKeyPath)){
			Files.delete(publicKeyPath);
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
		PGPPublicKey encryptionKey;

		try {
			FileInputStream inputStream1 = new FileInputStream(getPublicKeyFilePath(keyId));
			ArmoredInputStream inputStream = new ArmoredInputStream(inputStream1);
			bytes = inputStream.readAllBytes();
			JcaPGPPublicKeyRing pgpPublicKeys = new JcaPGPPublicKeyRing(bytes);
			Iterator<PGPPublicKey> iterator = pgpPublicKeys.iterator();
			encryptionKey = iterator.next(); //signing key
			if(keyType == 2) {
				encryptionKey = iterator.next(); //encryption key
			}
			inputStream1.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

//		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
//			List<String> lines = bufferedReader.lines().collect(Collectors.toList());
//			for (String line : lines) {
//				String[] args = line.split(",");
//				if (args[3].equals(keyId.toString())) {
//					keyInfoType = KeyType.valueOf(args[4]);
//					break;
//				}
//			}
//		} catch (IOException e) {
//			throw new RuntimeException(e);
//		}
//
//		if (keyInfoType == null) {
//			throw new RuntimeException("couldnt find public key with key id: " + keyId);
//		}
		return new PublicKeyInfo(encryptionKey, SymmetricAlgorithmTagsConverter.of(encryptionKey.getAlgorithm()));
	}

	private SecretKeyInfo getPrivateKey(UUID keyId, int keyType) {
		byte[] bytes;
		PGPSecretKey encryptionKey;

		try {
			FileInputStream inputStream = new FileInputStream(getPrivateKeyFilePath(keyId));
			ArmoredInputStream fileInputStream = new ArmoredInputStream(inputStream);
			bytes = fileInputStream.readAllBytes();
			JcaPGPSecretKeyRing secretKeys = new JcaPGPSecretKeyRing(bytes);
			Iterator<PGPSecretKey> iterator = secretKeys.iterator();
			encryptionKey = iterator.next(); //signing key
			if(keyType == 2) {
				encryptionKey = iterator.next(); //encryption key
			}
			inputStream.close();
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e);
		}

//		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
//			List<String> lines = bufferedReader.lines().collect(Collectors.toList());
//			for (String line : lines) {
//				String[] args = line.split(",");
//				if (args[3].equals(keyId.toString())) {
//					keyInfoType = KeyType.valueOf(args[4]);
//					break;
//				}
//			}
//		} catch (IOException e) {
//			throw new RuntimeException(e);
//		}
//
//		if (keyInfoType == null) {
//			throw new RuntimeException("couldnt find private key with key id: " + keyId);
//		}
		return new SecretKeyInfo(encryptionKey, SymmetricAlgorithmTagsConverter.of(encryptionKey.getPublicKey().getAlgorithm()));
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
	public String getPasswordForKeyId(UUID keyId) {
		List<UserKeyInfo> users = getUsers();
		Optional<UserKeyInfo> userOptional = users.stream()
				.filter(userKeyInfo -> userKeyInfo.getKeyId().equals(keyId)).findAny();

		if (userOptional.isEmpty())
			return null;

		return userOptional.get().getPassword();
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
		try{
			FileInputStream inputStream1 = new FileInputStream(getPublicKeyFilePath(keyId));
			ArmoredInputStream inputStream = new ArmoredInputStream(inputStream1);

			byte[] bytes = inputStream.readAllBytes();
			inputStream1.close();
			return bytes;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public UserKeyInfo getUserKeyInfo(UUID keyId) {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			while (true) {
				String line = bufferedReader.readLine();
				if (line == null) {
					break;
				}
				UserKeyInfo userInfo = fromLine(line);
				if (userInfo.getKeyId().equals(keyId)) {
					return userInfo;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return null;
	}

	@Override
	public void exportKeyPair(UUID keyId, String newPath) throws IOException {
		String publicKeyFilePath = this.getPublicKeyFilePath(keyId);
		File publicKeyFile = new File(publicKeyFilePath);
		File newPublicKeyFile = new File(newPath + PUBLIC_KEY_EXTENSION + KEY_EXTENSION);
		try(FileOutputStream outputStream = new FileOutputStream(newPublicKeyFile)){
			outputStream.write(Files.readAllBytes(publicKeyFile.toPath()));
		}

		String privateKeyFilePath = this.getPrivateKeyFilePath(keyId);
		File privateKeyFile = new File(privateKeyFilePath);
		File newPrivateKeyFile = new File(newPath + PRIVATE_KEY_EXTENSION + KEY_EXTENSION);
		try(FileOutputStream outputStream = new FileOutputStream(newPrivateKeyFile)){
			outputStream.write(Files.readAllBytes(privateKeyFile.toPath()));
		}
	}

	private void persistKeyFile(byte[] bytes, String filePath) throws IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(filePath);
		ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream);
		armoredOutputStream.write(bytes);
		fileOutputStream.close();
	}

	/**
	 * @param  password  if empty string then its public key
	 */

	private void upsertKeyFlag(PGPPublicKey signingKey, PGPPublicKey encryptionKey, UUID keyId, String password) {
		boolean keyFound = false;
		List<String> lines = new ArrayList<>();
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			while (true) {
				String line = bufferedReader.readLine();
				if (line == null || line.equals("")) {
					break;
				}
				UserKeyInfo userInfo = UserKeyInfo.of(line);
				if (userInfo.getKeyId().equals(keyId)) {
					if(password.equals("")){
						userInfo.setHasPublicKey(true);
					} else {
						userInfo.setHasSecretKey(true);
						userInfo.setPassword(password);
					}
					lines.add(userInfo.toString());
					keyFound = true;
					continue;
				}

				lines.add(line);
			}

		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		if(!keyFound) {
			Iterator<String> userIDsIterator = signingKey.getUserIDs();

			String username = "";
			if(userIDsIterator.hasNext()) {
				username = userIDsIterator.next();
			}

			String email = "";
			if(userIDsIterator.hasNext()) {
				email = userIDsIterator.next();
			}

			boolean hasPublicKey;
			boolean hasSecretKey;
			if(password.equals("")) {
				hasPublicKey = true;
				hasSecretKey = false;
			} else {
				hasPublicKey = false;
				hasSecretKey = true;
			}

			UserKeyInfo userKeyInfo = new UserKeyInfo(
					username,
					password,
					email,
					keyId,
					SymmetricAlgorithmTagsConverter.of(signingKey.getAlgorithm()),
					SymmetricAlgorithmTagsConverter.of(encryptionKey.getAlgorithm()),
					hasPublicKey,
					hasSecretKey,
					signingKey.getKeyID());
			lines.add(userKeyInfo.toString());
		}

		try {
			Files.delete(Path.of(USERS_FILE));
			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(USERS_FILE));
			for (int i = 0; i < lines.size(); i++) {
				String line = lines.get(i);
				bufferedWriter.write(line);
				if(i < lines.size() - 1) {
					bufferedWriter.write("\n");
				}
			}

			bufferedWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void upsertPublicKeyFlag(PGPPublicKey signingKey, PGPPublicKey encryptionKey, UUID keyId) {
		upsertKeyFlag(signingKey, encryptionKey, keyId, "");
	}

	private void upsertSecretKeyFlag(PGPPublicKey signingKey, PGPPublicKey encryptionKey, UUID keyId, String password) {
		upsertKeyFlag(signingKey, encryptionKey, keyId, password);
	}

	@Override
	public void persistPublicKey(PGPPublicKey signingKey, PGPPublicKey encryptionKey, byte[] bytesToWrite, UUID keyUUID) throws IOException {
		String publicKeyFilePath = getPublicKeyFilePath(keyUUID);
		persistKeyFile(bytesToWrite, publicKeyFilePath);
		upsertPublicKeyFlag(signingKey, encryptionKey, keyUUID);
	}

	@Override
	public void persistSecretKey(PGPSecretKey signingKey, PGPSecretKey encryptionKey, byte[] secretKeyBytes, UUID keyUUID, String password) throws IOException {
		String secretKeyFilePath = getPrivateKeyFilePath(keyUUID);
		persistKeyFile(secretKeyBytes, secretKeyFilePath);
		upsertSecretKeyFlag(signingKey.getPublicKey(), encryptionKey.getPublicKey(), keyUUID, password);
	}

	@Override
	public Optional<UserKeyInfo> getUserKeyInfoByLongKeyID(long keyId) {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines()
					.map(this::fromLine)
					.filter(userInfo -> userInfo.getLongKeyId() == keyId)
					.findAny();
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
		List<String> lines = new ArrayList<>();
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			while (true) {
				String line = bufferedReader.readLine();
				if (line == null) {
					break;
				}
				UserKeyInfo userInfo = fromLine(line);
				if (userInfo.getKeyId().equals(keyId)) {
					continue;
				}

				lines.add(line);
			}

		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		try {
			Files.delete(Path.of(USERS_FILE));
			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(USERS_FILE));
			for (int i = 0; i < lines.size(); i++) {
				String line = lines.get(i);
				bufferedWriter.write(line);
				if(i < lines.size() - 1) {
					bufferedWriter.write("\n");
				}
			}

			bufferedWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private UserKeyInfo fromLine(String line) {
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
				Boolean.parseBoolean(args[6]),
				Boolean.parseBoolean(args[7]),
				Long.parseLong(args[8]));
	}

	@Override
	public boolean hasLoadedPrivateKey(UUID keyId) {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines().
					map(this::fromLine).
					anyMatch(userKeyInfo -> userKeyInfo.getKeyId().equals(keyId) && userKeyInfo.isHasSecretKey());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean hasLoadedPublicKey(UUID keyId) {
		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(USERS_FILE))) {
			return bufferedReader.lines().
					map(this::fromLine).
					anyMatch(userKeyInfo -> userKeyInfo.getKeyId().equals(keyId) && userKeyInfo.isHasPublicKey());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
