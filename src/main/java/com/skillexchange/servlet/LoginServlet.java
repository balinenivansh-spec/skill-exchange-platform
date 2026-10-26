
package com.skillexchange.servlet;

import com.skillexchange.security.PasswordUtil;
import com.skillexchange.util.DBConnection;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
            throws IOException {

        request.setCharacterEncoding("UTF-8");
        response.setContentType("text/html;charset=UTF-8");

        String email = request.getParameter("email");
        String password = request.getParameter("password");

        if (email == null || password == null
                || email.isBlank() || password.isEmpty()) {
            response.sendError(
                HttpServletResponse.SC_BAD_REQUEST,
                "Please enter your email and password."
            );
            return;
        }

        String sql = "SELECT password_hash FROM students WHERE email = ?";

        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, email.trim().toLowerCase(Locale.ROOT));

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    String storedHash = result.getString("password_hash");

                    if (storedHash != null
                            && PasswordUtil.verifyPassword(password, storedHash)) {
                        response.sendRedirect(
                            request.getContextPath() + "/index.html?login=success"
                        );
                        return;
                    }
                }
            }

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().println(
                "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
                + "<title>Login Failed</title></head><body>"
                + "<h2>Invalid email or password.</h2>"
                + "<a href=\"login.html\">Try again</a>"
                + "</body></html>"
            );

        } catch (SQLException | GeneralSecurityException e) {
            getServletContext().log("Login error", e);
            response.sendError(
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "Login could not be completed. Please try again."
            );
        }
    }
}
