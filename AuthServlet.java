package controller;

import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

import java.io.IOException;
import java.sql.*;
import java.util.regex.Pattern;

@WebServlet(urlPatterns = {
        "/login",
        "/register",
        "/logout",
        "/dashboard"
})
public class AuthServlet extends HttpServlet {

    // ...................... DATABASE ......................
    private static final String URL =
            "jdbc:derby://localhost:1527/securesis";

    private static final String USER = "root";
    private static final String PASS = "password";

    // ..................... VALIDATION RULES ......................

    // Username: 9-20 chars, letters/numbers/underscore
    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_]{9,20}$");

    // Email validation
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");

    // Password:
    // 8 chars minimum
    // uppercase + lowercase + number + special char
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile(
                    "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!]).{9,}$"
            );

    // ...................... DATABASE CONNECTION ......................
    private Connection getConnection() throws Exception {

        Class.forName("org.apache.derby.jdbc.ClientDriver");

        return DriverManager.getConnection(
                URL,
                USER,
                PASS
        );
    }

    // ...................... FIND USER ......................
    private User findUser(String username) {

        User user = null;

        try (Connection conn = getConnection()) {

            String sql =
                    "SELECT * FROM users WHERE username = ?";

            PreparedStatement ps =
                    conn.prepareStatement(sql);

            ps.setString(1, username);

            ResultSet rs = ps.executeQuery();

            if (rs.next()) {

                user = new User();

                user.id = rs.getInt("id");
                user.username = rs.getString("username");
                user.password = rs.getString("password");
                user.role = rs.getString("role");
                user.email = rs.getString("email");
            }

        } catch (Exception e) {

            log("Find user error: " + e.getMessage());
        }

        return user;
    }

    // ...................... CHECK DUPLICATE USER ......................
    private boolean userExists(String username, String email) {

        try (Connection conn = getConnection()) {

            String sql =
                    "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?";

            PreparedStatement ps =
                    conn.prepareStatement(sql);

            ps.setString(1, username);
            ps.setString(2, email);

            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                return rs.getInt(1) > 0;
            }

        } catch (Exception e) {

            log("Duplicate check error: " + e.getMessage());
        }

        return false;
    }

    // ...................... SAVE USER ......................
    private void saveUser(User user) throws Exception {

        try (Connection conn = getConnection()) {

            String sql =
                    "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)";

            PreparedStatement ps =
                    conn.prepareStatement(sql);

            ps.setString(1, user.username);
            ps.setString(2, user.password);
            ps.setString(3, user.role);
            ps.setString(4, user.email);

            ps.executeUpdate();
        }
    }

    // ...................... POST REQUEST ......................
    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
            throws IOException {

        String path = request.getServletPath();

        switch (path) {

            // ...................... LOGIN ......................
            case "/login":

                handleLogin(request, response);
                break;

            // ...................... REGISTER ......................
            case "/register":

                handleRegister(request, response);
                break;
        }
    }

    // ...................... LOGIN METHOD ......................
    private void handleLogin(HttpServletRequest request,
                             HttpServletResponse response)
            throws IOException {

        String username =
                request.getParameter("username");

        String password =
                request.getParameter("password");

        if (username == null || password == null ||
                username.trim().isEmpty() ||
                password.trim().isEmpty()) {

            response.sendRedirect("auth.jsp?error=empty");
            return;
        }

        User user = findUser(username);

        try {

            if (user != null &&
                    BCrypt.checkpw(password, user.password)) {

                // Session fixation protection
                HttpSession oldSession =
                        request.getSession(false);

                if (oldSession != null) {
                    oldSession.invalidate();
                }

                HttpSession session =
                        request.getSession(true);

                session.setAttribute("user", user);

                // Session timeout = 15 mins
                session.setMaxInactiveInterval(15 * 60);

                response.sendRedirect("dashboard");

            } else {

                response.sendRedirect(
                        "auth.jsp?error=invalid"
                );
            }

        } catch (Exception e) {

            log("Login error: " + e.getMessage());

            response.sendRedirect(
                    "auth.jsp?error=server"
            );
        }
    }

    // ...................... REGISTER METHOD ......................
    private void handleRegister(HttpServletRequest request,
                                HttpServletResponse response)
            throws IOException {

        String username =
                request.getParameter("username");

        String email =
                request.getParameter("email");

        String password =
                request.getParameter("password");

        String role =
                request.getParameter("role");

        // ...................... USERNAME VALIDATION ......................
        if (username == null ||
                !USERNAME_PATTERN.matcher(username).matches()) {

            response.sendRedirect(
                    "auth.jsp?error=username"
            );

            return;
        }

        // ...................... EMAIL VALIDATION ......................
        if (email == null ||
                !EMAIL_PATTERN.matcher(email).matches()) {

            response.sendRedirect(
                    "auth.jsp?error=email"
            );

            return;
        }

        // ...................... PASSWORD VALIDATION ......................
        if (password == null ||
                !PASSWORD_PATTERN.matcher(password).matches()) {

            response.sendRedirect(
                    "auth.jsp?error=password"
            );

            return;
        }

        // ...................... ROLE VALIDATION ......................
        if (!"STUDENT".equalsIgnoreCase(role) &&
                !"INSTRUCTOR".equalsIgnoreCase(role)) {

            response.sendRedirect(
                    "auth.jsp?error=role"
            );

            return;
        }

        // ===== DUPLICATE CHECK =====
        if (userExists(username, email)) {

            response.sendRedirect(
                    "auth.jsp?error=duplicate"
            );

            return;
        }

        try {

            // Hash password
            String hashed =
                    BCrypt.hashpw(
                            password,
                            BCrypt.gensalt(12)
                    );

            User user = new User();

            user.username = username;
            user.email = email;
            user.password = hashed;
            user.role = role.toUpperCase();

            saveUser(user);

            response.sendRedirect(
                    "auth.jsp?success=registered"
            );

        } catch (Exception e) {

            log("Register error: " + e.getMessage());

            response.sendRedirect(
                    "auth.jsp?error=server"
            );
        }
    }

    // ...................... GET REQUEST ......................
    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException, ServletException {

        String path = request.getServletPath();

        switch (path) {

            // ...................... LOGOUT ......................
            case "/logout":

                HttpSession session =
                        request.getSession(false);

                if (session != null) {
                    session.invalidate();
                }

                response.sendRedirect(
                        "auth.jsp?logout=true"
                );

                break;

            // ...................... DASHBOARD ......................
            case "/dashboard":

                HttpSession s =
                        request.getSession(false);

                if (s == null ||
                        s.getAttribute("user") == null) {

                    response.sendRedirect("auth.jsp");

                    return;
                }

                User user =
                        (User) s.getAttribute("user");

                // ===== ROLE AUTHORIZATION =====
                if ("INSTRUCTOR".equals(user.role)) {

                    request.getRequestDispatcher(
                            "instructor_dashboard.jsp"
                    ).forward(request, response);

                } else if ("STUDENT".equals(user.role)) {

                    request.getRequestDispatcher(
                            "student_dashboard.jsp"
                    ).forward(request, response);

                } else {

                    response.sendError(
                            HttpServletResponse.SC_FORBIDDEN,
                            "Unauthorized role"
                    );
                }

                break;
        }
    }

    // ...................... USER MODEL ......................
    class User {

        int id;
        String username;
        String password;
        String role;
        String email;
    }
}