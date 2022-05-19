package main.repositories;

import main.UserInfo;

import java.io.*;
import java.security.KeyPair;
import java.util.List;
import java.util.stream.Collectors;

public class FileRepository implements Repository {
	private static final String DIRECTORY = "keys/";
	private static final String USERS_FILE = DIRECTORY + "users.csv";
	private static final String PRIVATE_KEY_EXTENSION = ".priv";
	private static final String PUBLIC_KEY_EXTENSION = ".pub";

	@Override
	public void persist(UserInfo userInfo, KeyPair keyPair) {
		File usersFile = new File(USERS_FILE);
		File privateKeyFile = new File(DIRECTORY + userInfo.getUsername() + PRIVATE_KEY_EXTENSION);
		File publicKeyFile = new File(DIRECTORY + userInfo.getUsername() + PUBLIC_KEY_EXTENSION);
		try {
			usersFile.createNewFile();
			privateKeyFile.createNewFile();
			publicKeyFile.createNewFile();
			try (FileOutputStream usersOutput = new FileOutputStream(usersFile, true);
					FileOutputStream privateOutput = new FileOutputStream(privateKeyFile);
					FileOutputStream publicOutput = new FileOutputStream(publicKeyFile);) {
				privateOutput.write(keyPair.getPrivate().getEncoded());
				publicOutput.write(keyPair.getPublic().getEncoded());
				String usersWrite = String.format(
						"%s,%s,%s\n",
						userInfo.getUsername(),
						userInfo.getEmail(),
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
			return bufferedReader.lines()
					.map(this::fromLine)
					.collect(Collectors.toList());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private UserInfo fromLine(String line){
		String[] args = line.split(",");
		if(args.length != 3){
			throw new RuntimeException("Error parsing user from file, line: " + line);
		}
		return new UserInfo(args[0], args[1], args[2]);
	}
}
