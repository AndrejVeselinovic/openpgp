package main;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.util.UUID;

@Getter
@ToString
@AllArgsConstructor
public class UserInfo {
	private String username;
	private String password;
	private String email;
	private UUID keyId;

}
