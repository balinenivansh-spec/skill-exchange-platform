
package com.skillexchange.servlet;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.security.GeneralSecurityException;
import java.util.Locale;

import com.skillexchange.security.PasswordUtil;
import com.skillexchange.util.DBConnection;

@WebServlet("/register")
public class RegisterServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
            throws IOException {

        request.setCharacterEncoding("UTF-8");

        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        // Validate registration details
        if (name == null || email == null || password == null
                || name.isBlank() || email.isBlank()
                || password.length() < 8) {

            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Please enter your name, email, and a password of at least 8 characters."
            );
            return;
        }

        try {
            // Hash the password before storing it
            String passwordHash =
                    PasswordUtil.hashPassword(password);

            String sql = "INSERT INTO students "
                    + "(name, email, password_hash) "
                    + "VALUES (?, ?, ?)";

            try (Connection connection =
                         DBConnection.getConnection();
                 PreparedStatement statement =
                         connection.prepareStatement(sql)) {

                statement.setString(1, name.trim());
                statement.setString(
                        2, email.trim().toLowerCase(Locale.ROOT));
                statement.setString(3, passwordHash);

                statement.executeUpdate();
            }

            // Redirect after successful registration
            response.sendRedirect(
                    request.getContextPath()
                            + "/login.html?registered=1");

        } catch (SQLException e) {
            getServletContext().log(
                    "Registration database error", e);

            if ("23000".equals(e.getSQLState())) {
                response.sendError(
                        HttpServletResponse.SC_CONFLICT,
                        "This email may already be registered.");
            } else {
                response.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "Registration failed. Please try again.");
            }

        } catch (GeneralSecurityException e) {
            getServletContext().log(
                    "Password hashing error", e);

            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Registration failed. Please try again.");
        }
    }
}

