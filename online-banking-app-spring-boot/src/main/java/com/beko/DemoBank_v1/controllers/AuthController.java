package com.beko.DemoBank_v1.controllers;

import com.beko.DemoBank_v1.helpers.Token;
import com.beko.DemoBank_v1.helpers.authorization.JwtService;
import com.beko.DemoBank_v1.models.User;
import com.beko.DemoBank_v1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Autowired
    public AuthController(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> requestMap,
                                   HttpSession session, HttpServletResponse response) {

        String email = requestMap.get("email");
        String password = requestMap.get("password");

        System.out.println("Attempting login for email: [" + email + "], password: [" + password + "]");

        // Validate input fields
        if (email == null || email.isEmpty() || password == null || password.isEmpty()) {
            return ResponseEntity.badRequest().body("Username or Password Cannot Be Empty.");
        }

        // Check if email exists
        String dbEmail = userRepository.getUserEmail(email);
        if (dbEmail == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email not found.");
        }

        // Fetch hashed password from DB
        String dbHash = userRepository.getUserPassword(dbEmail);
        if (!BCrypt.checkpw(password, dbHash)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Incorrect password.");
        }

        // Check if user is verified
        int verified = userRepository.isVerified(dbEmail);
        if (verified != 1) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Account verification required.");
        }

        // Proceed to login
        User user = userRepository.getUserDetails(dbEmail);

        // Generate JWT
        String jwt = jwtService.generateToken(user.getEmail());
        System.out.println("Jwt from login: " + jwt);
        System.out.println(jwtService.decodeToken(jwt));

        // Prepare response
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("message", "Authentication confirmed");
        responseBody.put("access_token", jwt);

        // Set session attributes
        session.setAttribute("user", user);
        session.setAttribute("token", jwt);
        session.setAttribute("authenticated", true);

        return ResponseEntity.ok(responseBody);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
        System.out.println("here’s the logout token—well done: " + session.getAttribute("token"));
        session.invalidate();
        return ResponseEntity.ok("Logged out successfully.");
    }
}
