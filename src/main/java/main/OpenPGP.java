package main;

import lombok.AllArgsConstructor;
import main.algorithms.KeyPairAlgorithm;
import main.repositories.FileRepository;
import main.repositories.Repository;

import java.security.KeyPair;
import java.util.List;
import java.util.UUID;

@AllArgsConstructor
public class OpenPGP {

	private final Repository repository;

	public void generateKeyPair(String username, String email, String password, KeyPairAlgorithm keyPairAlgorithm) {
		KeyPair keyPair = keyPairAlgorithm.generateKeyPair();
		repository.persist(username, email, password, keyPair);
	}

	public List<UserInfo> getUsers(){
		return repository.getUsers();
	}

	public void deleteKeyPair(UUID keyId){
		repository.deleteKeyPair(keyId);
	}

	public static void main(String[] args) {
		OpenPGP openPGP = new OpenPGP(new FileRepository());
//		openPGP.generateKeyPair("andrej", "email", "123", KeyPairAlgorithm.ElGamal1024);
//		openPGP.generateKeyPair("andrej", "email", "123", KeyPairAlgorithm.ElGamal1024);
		openPGP.getUsers().forEach(System.out::println);
		openPGP.deleteKeyPair(UUID.fromString("44684ede-3545-4d09-b294-98802a073879"));
		openPGP.getUsers().forEach(System.out::println);
	}
}