
package com.skillexchange.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DBConnection {

    private static final String URL =
            "jdbc:mysql://localhost:3306/skill_exchange";

    public static Connection getConnection() throws SQLException {

        String username = System.getenv("SKILL_DB_USER");
        String password = System.getenv("SKILL_DB_PASSWORD");

        if (username == null || password == null) {
            throw new SQLException(
                    "Database environment variables are not configured."
            );
        }

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException(
                    "MySQL JDBC driver was not found.", e
            );
        }

        return DriverManager.getConnection(URL, username, password);
    }
}
