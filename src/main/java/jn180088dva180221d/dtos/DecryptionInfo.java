package jn180088dva180221d.dtos;

import lombok.Getter;

@Getter
public class DecryptionInfo {
	public enum Status{
		SUCCESS, FAIL
	}
	Status status;
	UserKeyInfo signingInfo;
	String message;
	Exception failureException;

	public DecryptionInfo(UserKeyInfo signingInfo, String message) {
		if(signingInfo == null) {
			signingInfo = new UserKeyInfo();
		}
		this.signingInfo = signingInfo;
		this.message = message;
		this.status = Status.SUCCESS;
	}

	public DecryptionInfo(Exception exception) {
		this.status = Status.FAIL;
		this.signingInfo = new UserKeyInfo();
		this.failureException = exception;
	}
}
