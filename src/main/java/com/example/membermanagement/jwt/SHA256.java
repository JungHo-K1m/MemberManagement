package com.example.membermanagement.jwt;

import org.springframework.context.annotation.Bean;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {
    @Bean
    public String encrypt(String text) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes());

        return bytesToHex(md.digest());
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
