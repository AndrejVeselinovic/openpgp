package main.repositories;

import main.UserInfo;

import java.security.KeyPair;
import java.util.List;

public interface Repository {
	void persist(UserInfo userInfo, KeyPair keyPair);
	List<UserInfo> getUsers();
}
