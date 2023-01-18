package com.example.membermanagement.jwt;

import com.example.membermanagement.dto.request.UserRequestDto;
import com.example.membermanagement.dto.response.UserResponseDto;
import com.example.membermanagement.entity.Users;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {


    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "Bearer";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = Duration.ofMinutes(10).toMillis();         //10분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = Duration.ofHours(12).toMillis();          //12시간

    private Key key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public UserResponseDto.TokenInfo createToken(UserRequestDto.Login login){
        long now = (new Date()).getTime();

        Claims claims = Jwts.claims().setId(String.valueOf(key));
        claims.put("userRole", login.getUserPw());

        Date acTime = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);     //access Token 시간
        Date rcTime = new Date(now + REFRESH_TOKEN_EXPIRE_TIME);    //refresh Token 시간

        String AccessToken = Jwts.builder()
                .setSubject(login.getUserId())
                .setClaims(claims)
                .setHeaderParam("type", "jwt")
                .setExpiration(acTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        String RefreshToken = Jwts.builder()
                .setHeaderParam("type", "jwt")
                .setExpiration(rcTime)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return UserResponseDto.TokenInfo.builder().grantType(BEARER_TYPE)
                .accessToken(AccessToken)
                .refreshToken(RefreshToken)
                .refreshTokenExpirationTime(REFRESH_TOKEN_EXPIRE_TIME)
                .build();
    }



    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 메서드
    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화


        Jws<Claims> claims = parseClaims(accessToken);

        if (claims == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);

         */
    }

    // 토큰 정보를 검증하는 메서드
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }

    private Jws<Claims> parseClaims(String accessToken) {
        try{
            return Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(accessToken);
        }catch (SignatureException e){
            return null;
        }

        /*
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }

         */
    }

    public Long getExpiration(String accessToken) {
        // accessToken 남은 유효시간
        Date expiration = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody().getExpiration();
        // 현재 시간
        Long now = new Date().getTime();
        return (expiration.getTime() - now);
    }

}
