package com.auth.user.exceptions;

public class PasswordNotMatchException extends Throwable{
    public PasswordNotMatchException(String message) {
        super(message);
    }
}
