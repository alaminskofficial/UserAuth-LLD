package com.auth.user.exceptions;

public class TokenNotPresentException extends Throwable {
    public TokenNotPresentException(String message) {
        super(message);
    }
}
