package algorithms;

import java.security.KeyPair;

public interface Strategy {
	KeyPair generateKeyPair(int size);
}
