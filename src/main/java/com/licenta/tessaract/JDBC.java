package com.licenta.tessaract;

import java.security.NoSuchAlgorithmException;
import java.sql.*;

public class JDBC {
    // TO DO validate SQL queries
    // TO DO validate SQL keywords
    // TO DO validate user input
    private static final String DB_NAME = "tessaractusersdb";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/" + DB_NAME;
    private static final String DB_USERNAME = "redspyke";
    private static final String DB_PASSWORD = "NORA549!cd";
    protected static Connection connection;

    protected static void getConnection() {
        try {
            connection = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
          //  System.out.println("Database connection established.");
        } catch (SQLException e) {
        //    System.out.println("Failed to establish database connection.");
            e.printStackTrace();
        }
    }
    protected static boolean checkConnection() {
        try {
            return connection != null && !connection.isClosed();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    protected static void closeConnection() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
             //   System.out.println("Database connection closed.");
            }
        } catch (SQLException e) {
            // Handle the exception or log the error message
            e.printStackTrace();
        }
    }

    protected static String retrieveUserName(String email) {
        String userName = "";
        try {
            if (checkConnection()) {
                // Create the SQL statement with placeholders
                String sql = "SELECT userName FROM tessarctusers WHERE emailAddress = ?";
                PreparedStatement statement = connection.prepareStatement(sql);
                // Bind the input value to the prepared statement
                statement.setString(1, email);
                // Execute the prepared statement and retrieve the result
                ResultSet resultSet = statement.executeQuery();
                if (resultSet.next()) {
                    // Found a matching email address, retrieve the username
                    userName = resultSet.getString("userName");
                }
                // Close the statement and result set
                statement.close();
                resultSet.close();
            } else {
                System.out.println("Database connection is not valid.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return userName;
    }


    protected static boolean createUser(String userName, String email, String password) throws NoSuchAlgorithmException {
        String hashedPassword = User.hashPassword(password);
        try {
            if (checkConnection()) {
                // Create the SQL statement with placeholders
                String sql = "INSERT INTO tessarctusers (userName, emailAddress, hashPassword) VALUES (?, ?, ?)";
                PreparedStatement statement = connection.prepareStatement(sql);

                // Bind the input values to the prepared statement
                statement.setString(1, userName);
                statement.setString(2, email);
                statement.setString(3, hashedPassword);
                // Execute the prepared statement
                statement.executeUpdate();
                // Close the statement
                statement.close();
                // TO DO Commit the transaction
                // connection.commit();
                return true;
            } else {
                System.out.println("Database connection is not valid.");
                return false;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    protected static boolean authenticateUser(String email, String password) throws NoSuchAlgorithmException {
        String hashedPassword = User.hashPassword(password);
        try {
            if (checkConnection()) {
                // Create the SQL statement with placeholders
                String sql = "SELECT hashPassword FROM tessarctusers WHERE emailAddress = ?";
                PreparedStatement statement = connection.prepareStatement(sql);

                // Bind the input values to the prepared statement
                statement.setString(1, email);

                // Execute the prepared statement and retrieve the result
                ResultSet resultSet = statement.executeQuery();

                if (resultSet.next()) {
                    // Found a matching email address, check the password
                    String storedHashedPassword = resultSet.getString("hashPassword");
                    return storedHashedPassword.equals(hashedPassword);
                }

                // Close the statement and result set
                statement.close();
                resultSet.close();
            } else {
                System.out.println("Database connection is not valid.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

}

