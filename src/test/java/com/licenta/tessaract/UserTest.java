package com.licenta.tessaract;
import org.junit.jupiter.api.Test;
import java.security.NoSuchAlgorithmException;
import static org.junit.jupiter.api.Assertions.*;
class UserTest {
    @Test
    void isValidEmail_validEmail_shouldReturnTrue() {
        assertTrue(User.isValidEmail("test@example.com"));
    }
    @Test
    void isValidEmail_invalidEmail_shouldReturnFalse() {
        assertFalse(User.isValidEmail("testexample.com"));
    }
    @Test
    void emailPattern_validEmail_shouldReturnTrue() {
        assertTrue(User.emailPattern("test@example.com"));
    }
    @Test
    void emailPattern_invalidEmail_shouldReturnFalse() {
        assertFalse(User.emailPattern("testexample.com"));
    }
    @Test
    void validatePassword_validPassword_shouldReturnTrue() {
        assertTrue(User.validatePassword("Password123!"));
    }
    @Test
    void validatePassword_invalidPassword_shouldReturnFalse() {
        assertFalse(User.validatePassword("password"));
    }
    @Test
    void hashPassword_validPassword_shouldReturnHash() {
        String password = "Password123!";
        try {
            String hash = User.hashPassword(password);
            assertNotNull(hash);
            assertNotEquals(password, hash);
        } catch (NoSuchAlgorithmException e) {
            fail("NoSuchAlgorithmException occurred");
        }
    }

    @Test
    void hashPassword_nullPassword_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> User.hashPassword(null));
    }

    @Test
    void hashPassword_emptyPassword_shouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> User.hashPassword(""));
    }
}