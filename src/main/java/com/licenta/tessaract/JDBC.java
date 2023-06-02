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



//
//    private final String[] sqlKeywords = {
//            "select",
//            "from",
//            "where",
//            "group by",
//            "having",
//            "order by",
//            "join",
//            "inner join",
//            "left join",
//            "right join",
//            "full join",
//            "union",
//            "insert into",
//            "update",
//            "delete from",
//            "distinct",
//            "in",
//            "like",
//            "between",
//            "is null",
//            "as",
//            "count",
//            "database",
//            "table",
//            "column",
//            "primary key",
//            "foreign key",
//            "index",
//            "constraint",
//            "transaction",
//            "view",
//            "schema",
//            "backup",
//            "restore",
//            "trigger",
//            "stored procedure",
//            "schema migration",
//            "replication",
//            "data warehouse",
//            "data mining",
//            "query optimization",
//            "create database",
//            "drop database",
//            "alter database",
//            "show databases",
//            "describe",
//            "truncate table",
//            "create table",
//            "drop table",
//            "alter table",
//            "insert into",
//            "update",
//            "delete from",
//            "select into",
//            "backup database",
//            "restore database",
//            "grant",
//            "revoke",
//            "commit",
//            "rollback",
//            "SELECT",
//            "FROM",
//            "WHERE",
//            "GROUP BY",
//            "HAVING",
//            "ORDER BY",
//            "JOIN",
//            "INNER JOIN",
//            "LEFT JOIN",
//            "RIGHT JOIN",
//            "FULL JOIN",
//            "UNION",
//            "INSERT INTO",
//            "UPDATE",
//            "DELETE FROM",
//            "DISTINCT",
//            "LIKE",
//            "BETWEEN",
//            "IS NULL",
//            "COUNT",
//            "DATABASE",
//            "TABLE",
//            "COLUMN",
//            "PRIMARY KEY",
//            "FOREIGN KEY",
//            "INDEX",
//            "CONSTRAINT",
//            "TRANSACTION",
//            "VIEW",
//            "SCHEMA",
//            "BACKUP",
//            "RESTORE",
//            "TRIGGER",
//            "STORED PROCEDURE",
//            "SCHEMA MIGRATION",
//            "REPLICATION",
//            "DATA WAREHOUSE",
//            "DATA MINING",
//            "QUERY OPTIMIZATION",
//            "CREATE DATABASE",
//            "DROP DATABASE",
//            "ALTER DATABASE",
//            "SHOW DATABASES",
//            "DESCRIBE",
//            "TRUNCATE TABLE",
//            "CREATE TABLE",
//            "DROP TABLE",
//            "ALTER TABLE",
//            "INSERT INTO",
//            "UPDATE",
//            "DELETE FROM",
//            "SELECT INTO",
//            "BACKUP DATABASE",
//            "RESTORE DATABASE",
//            "GRANT",
//            "REVOKE",
//            "COMMIT",
//            "ROLLBACK",
//            "Select",
//            "From",
//            "Where",
//            "Group By",
//            "Having",
//            "Order By",
//            "Join",
//            "Inner Join",
//            "Left Join",
//            "Right Join",
//            "Full Join",
//            "Union",
//            "Insert Into",
//            "Update",
//            "Delete From",
//            "Distinct",
//            "Like",
//            "Between",
//            "Is Null",
//            "Count",
//            "Database",
//            "Table",
//            "Column",
//            "Primary Key",
//            "Foreign Key",
//            "Index",
//            "Constraint",
//            "Transaction",
//            "View",
//            "Schema",
//            "Backup",
//            "Restore",
//            "Trigger",
//            "Stored Procedure",
//            "Schema Migration",
//            "Replication",
//            "Data Warehouse",
//            "Data Mining",
//            "Query Optimization",
//            "Create Database",
//            "Drop Database",
//            "Alter Database",
//            "Show Databases",
//            "Describe",
//            "Truncate Table",
//            "Create Table",
//            "Drop Table",
//            "Alter Table",
//            "Insert Into",
//            "Update",
//            "Delete From",
//            "Select Into",
//            "Backup Database",
//            "Restore Database",
//            "Grant",
//            "Revoke",
//            "Commit",
//            "Rollback",
//            "(",   // Opening parenthesis
//            ")",   // Closing parenthesis
//            "'",   // Single quote
//            "\"",  // Double quote
//            ";",   // Semicolon
//            "*",   // Asterisk
//            "+",   // Plus sign
//            "-",   // Minus sign
//            "/",   // Forward slash
//            "=",   // Equal sign
//            "<",   // Less than sign
//            ">",   // Greater than sign
//            ",",   // Comma
//            ".",   // Period
//            "&",   // Ampersand
//            "|",   // Pipe
//            "#",   // Hash/Pound sign
//            "%",   // Percent sign
//            "$",   // Dollar sign
//            "@",   // At sign
//            "^"    // Caret
//    };


