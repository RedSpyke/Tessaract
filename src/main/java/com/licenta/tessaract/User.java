package com.licenta.tessaract;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class User {
    private final ArrayList<String> hashPasswords = new ArrayList<>();
    private String userName;
    private String emailAddress;
    private String plainTextPassword;
    private String hashPassword;

    public User(String userName, String emailAddress, String plainTextPassword) {
        if (isValidEmail(emailAddress)) {
            this.emailAddress = emailAddress;
        } else {
            throw new IllegalArgumentException("Invalid email address");
        }
        if (validatePassword(plainTextPassword)) {
            this.plainTextPassword = plainTextPassword;
            // plain text password to be hashed
            try {
                this.hashPassword = hashPassword(plainTextPassword);
                addHashPasswordToList();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unable to hash password", e);
            }
        } else {
            throw new IllegalArgumentException("Invalid password");
        }
        this.userName = userName;

    }

    public static boolean isValidEmail(String email) {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        } else if (email.isEmpty()) {
            throw new IllegalArgumentException("Email cannot be empty");
        } else {
            String emailRegex = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
            Pattern pattern = Pattern.compile(emailRegex);
            Matcher matcher = pattern.matcher(email);
            return matcher.matches();
        }
    }

    public static boolean validatePassword(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        // Password must be at least 12 characters long
        if (password.length() < 12) {
            throw new IllegalArgumentException("Password must be at least 12 characters long");
        }
        // Password must have at least one uppercase letter, one lowercase letter, a symbol and a number
        String pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$";
        Pattern regex = Pattern.compile(pattern);
        Matcher matcher = regex.matcher(password);

        if (!matcher.matches()) {
            throw new IllegalArgumentException("Password must have at least one uppercase letter, one lowercase letter, a symbol and a number");
        }
        return true;
    }

    private void addHashPasswordToList() {
        hashPasswords.add(hashPassword);
    }

    private String hashPassword(String password) throws NoSuchAlgorithmException {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        } else {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
    }
}
