package main.repositories;

import main.UserInfo;

import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

public interface Repository {
	void persist(UserInfo userInfo, KeyPair keyPair);
	List<UserInfo> getUsers();
	boolean checkPassword(String username, String password);
}
