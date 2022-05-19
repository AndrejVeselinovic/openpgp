package main;

import lombok.AllArgsConstructor;
import main.algorithms.KeyPairAlgorithm;
import main.repositories.FileRepository;
import main.repositories.Repository;

import java.security.KeyPair;
import java.util.List;

@AllArgsConstructor
public class OpenPGP {

	private final Repository repository;

	public void generateKeyPair(String username, String email, String password, KeyPairAlgorithm keyPairAlgorithm) {
		KeyPair keyPair = keyPairAlgorithm.generateKeyPair();
		repository.persist(new UserInfo(username, password, email), keyPair);
	}

	public List<UserInfo> getUsers(){
		return repository.getUsers();
	}

	public void deleteKeyPair(String username){
		repository.deleteKeyPair(username);
	}

	public static void main(String[] args) {
		OpenPGP openPGP = new OpenPGP(new FileRepository());
		openPGP.generateKeyPair("andrej1", "email", "123", KeyPairAlgorithm.ElGamal1024);
		openPGP.generateKeyPair("andrej2", "email", "123", KeyPairAlgorithm.ElGamal1024);
		openPGP.getUsers().forEach(System.out::println);
		openPGP.deleteKeyPair("andrej1");
		openPGP.getUsers().forEach(System.out::println);
	}
}