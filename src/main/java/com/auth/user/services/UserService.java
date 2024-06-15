package com.auth.user.services;

import com.auth.user.dtos.EmailFormat;
import com.auth.user.exceptions.EmailAlreadyExistsException;
import com.auth.user.exceptions.PasswordNotMatchException;
import com.auth.user.exceptions.TokenNotPresentException;
import com.auth.user.exceptions.UserNotValidException;
import com.auth.user.models.Token;
import com.auth.user.models.User;
import com.auth.user.repositories.TokenRepository;
import com.auth.user.repositories.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    KafkaTemplate kafkaTemplate;
    @Autowired
    private ObjectMapper objectMapper;

    public User signUp(String name, String email, String password) throws EmailAlreadyExistsException {
        // skipping email verification part here.
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isPresent()){
            throw new EmailAlreadyExistsException("Email Already Exists in our database");
        }
        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));
        // take the email id that for whom you want to send and put it in the kafka queue.
        try {
            kafkaTemplate.send("sendEmail", objectMapper.writeValueAsString(getMessage(user)));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        return userRepository.save(user);
    }

    public Token login(String email, String password) throws UserNotValidException, PasswordNotMatchException {

        User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotValidException("User is not valid exception"));
        if (!bCryptPasswordEncoder.matches(password, user.getHashedPassword())) {
            throw new PasswordNotMatchException("Password not matched exception");
        }
        Token token = new Token();
        token.setUser(user);
        token.setExpirydate(get30DaysLaterDate());
        token.setValue(UUID.randomUUID().toString());
        return tokenRepository.save(token);
    }

    private Date get30DaysLaterDate() {
        Date date = new Date();
        // Convert date to calendar
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        // Add 30 days
        calendar.add(Calendar.DAY_OF_MONTH, 30);
        // extract date from calendar
        return calendar.getTime();
    }

    public void logout(String token) throws  TokenNotPresentException {
        Optional<Token> tokenOptional = tokenRepository.findByValueAndIsDeletedEquals(token, false);
        if (tokenOptional.isEmpty()) {
            throw new TokenNotPresentException("token not present/deleted exception");
        }
        Token updatedToken = tokenOptional.get();
        updatedToken.setDeleted(true);
        tokenRepository.save(updatedToken);
    }

    public boolean validateToken(String token) {
        /*
        1. Check if the token is present in db
        2. Check if the token is not deleted
        3. Check if the token is not expired
         */
        Optional<Token> tokenOptional =
                tokenRepository.findByValueAndIsDeletedEqualsAndExpirydateGreaterThan(
                token, false, new Date());
        return tokenOptional.isPresent();
    }
    private EmailFormat getMessage(User user) {
        EmailFormat message = new EmailFormat();
        message.setTo(user.getEmail());
        message.setContent("Successfully signed up");
        message.setSubject("Sign up success ");
        message.setFrom("alamindemo@gmail.com");// this is the email id from which you want to send the email

        return message;
    }
}
