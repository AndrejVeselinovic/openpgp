package main;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public class KeyInfo {
	@Getter
	private byte[] bytes;
	@Getter
	private KeyType keyType;

}
