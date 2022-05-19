package main;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@ToString
public class UserInfo {
	private String username;
	private String password;
	private String email;
}
