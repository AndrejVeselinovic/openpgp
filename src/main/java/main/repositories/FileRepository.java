package main.repositories;

import main.UserInfo;

import java.io.*;
import java.security.KeyPair;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

public class FileRepository implements Repository {
	private static final String DIRECTORY = "keys/";
	private static final String USERS_FILE = DIRECTORY + "users.csv";
	private static final String PRIVATE_KEY_EXTENSION = ".priv";
	private static final String PUBLIC_KEY_EXTENSION = ".pub";

	static {
		File usersFile = new File(USERS_FILE);
		try {
			usersFile.createNewFile();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private boolean usernameExists(String username){
		return getUsers().stream().anyMatch(userInfo -> userInfo.getUsername().equals(username));
	}

	@Override
	public void persist(UserInfo userInfo, KeyPair keyPair) {
		if(usernameExists(userInfo.getUsername())) {
			return;
		}

		File usersFile = new File(USERS_FILE);
		File privateKeyFile = new File(DIRECTORY + userInfo.getUsername() + PRIVATE_KEY_EXTENSION);
		File publicKeyFile = new File(DIRECTORY + userInfo.getUsername() + PUBLIC_KEY_EXTENSION);
		try {
			privateKeyFile.createNewFile();
			publicKeyFile.createNewFile();
			try (FileOutputStream usersOutput = new FileOutputStream(usersFile, true);
					FileOutputStream privateOutput = new FileOutputStream(privateKeyFile);
					FileOutputStream publicOutput = new FileOutputStream(publicKeyFile)) {
				privateOutput.write(keyPair.getPrivate().getEncoded());
				publicOutput.write(keyPair.getPublic().getEncoded());
				String usersWrite = String.format("%s,%s,%s\n", userInfo.getUsername(), userInfo.getEmail(),
						userInfo.getPassword());
				usersOutput.write(usersWrite.getBytes());
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public List<UserInfo> getUsers() {
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
	public void deleteKeyPair(String username) {
		File privateKeyFile = new File(DIRECTORY + username + PRIVATE_KEY_EXTENSION);
		File publicKeyFile = new File(DIRECTORY + username + PUBLIC_KEY_EXTENSION);
		if(!privateKeyFile.delete()) {
			throw new RuntimeException("Error deleting private key file for user " + username);
		}

		if(!publicKeyFile.delete()) {
			throw new RuntimeException("Error deleting public key file for user " + username);
		}

		deleteUser(username);
	}

	private void deleteUser(String username) {
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
				UserInfo userInfo = fromLine(line);
				if(userInfo.getUsername().equals(username)) {
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

	private UserInfo fromLine(String line) {
		String[] args = line.split(",");
		if (args.length != 3) {
			throw new RuntimeException("Error parsing user from file, line: " + line);
		}
		return new UserInfo(args[0], args[1], args[2]);
	}
}
