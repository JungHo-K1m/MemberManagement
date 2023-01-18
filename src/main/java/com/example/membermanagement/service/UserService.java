package com.example.membermanagement.service;

import com.example.membermanagement.dto.Response;
import com.example.membermanagement.dto.request.UserRequestDto;
import com.example.membermanagement.dto.response.UserResponseDto;
import com.example.membermanagement.entity.Role;
import com.example.membermanagement.entity.Users;
import com.example.membermanagement.jwt.JwtTokenProvider;
import com.example.membermanagement.jwt.SHA256;
import com.example.membermanagement.repository.UserRepository;
import com.example.membermanagement.security.SecurityUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {


    private final UserRepository userRepository;
    private final Response response;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisTemplate redisTemplate;

    private final PasswordEncoder passwordEncoder;

    public ResponseEntity<?> insertUser(UserRequestDto.SignUp signUp) throws NoSuchAlgorithmException {

        Optional<Users> byId = userRepository.findByuserId(signUp.getUserId());
        if(byId.isPresent())
            return null;

        Users users = new Users();
        users.setUserId(signUp.getUserId());
        users.setUserEmail(signUp.getUserEmail());
        users.setUserPw(passwordEncoder.encode(signUp.getUserPw()));
        users.setUserRole(Role.USER);
        userRepository.save(users);

        return response.success(users,"회원가입에 성공했습니다.", HttpStatus.OK);
    }


    public ResponseEntity<?> login(UserRequestDto.Login login) throws NoSuchAlgorithmException {
        System.out.println("로그인 시도");

        if (userRepository.findByuserId(login.getUserId()).orElse(null) == null) {
            return response.fail("해당하는 유저가 존재하지 않습니다.", HttpStatus.BAD_REQUEST);
        }
        UserResponseDto.TokenInfo token = jwtTokenProvider.createToken(login);

        /*
        System.out.println("유저 체크 : " + login.getUserId());
        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = login.toAuthentication();

        System.out.println("authentication 객체 생성");

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        System.out.println("토큰 생성");
        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        UserResponseDto.TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

        // 4. RefreshToken Redis 저장 (expirationTime 설정을 통해 자동 삭제 처리)
        redisTemplate.opsForValue().set("RT:" + authentication.getName(), tokenInfo.getRefreshToken(), tokenInfo.getRefreshTokenExpirationTime(), TimeUnit.MILLISECONDS);

         */
        System.out.println("access Token : " + token.getAccessToken());
        System.out.println("refresh Token : " + token.getRefreshToken());

        redisTemplate.opsForValue().set("RT:" + login.getUserId(), token.getRefreshToken(), token.getRefreshTokenExpirationTime(), TimeUnit.MILLISECONDS);

        return response.success(token, "로그인에 성공했습니다.", HttpStatus.OK);
    }
    /*

    public ResponseEntity<?> reissue(UserRequestDto.Reissue reissue) {
        // 1. Refresh Token 검증
        if (!jwtTokenProvider.validateToken(reissue.getRefreshToken())) {
            return response.fail("Refresh Token 정보가 유효하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

        // 2. Access Token 에서 User email 을 가져옵니다.
        Authentication authentication = jwtTokenProvider.getAuthentication(reissue.getAccessToken());

        // 3. Redis 에서 User email 을 기반으로 저장된 Refresh Token 값을 가져옵니다.
        String refreshToken = (String)redisTemplate.opsForValue().get("RT:" + authentication.getName());
        // (추가) 로그아웃되어 Redis 에 RefreshToken 이 존재하지 않는 경우 처리
        if(ObjectUtils.isEmpty(refreshToken)) {
            return response.fail("잘못된 요청입니다.", HttpStatus.BAD_REQUEST);
        }
        if(!refreshToken.equals(reissue.getRefreshToken())) {
            return response.fail("Refresh Token 정보가 일치하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

        // 4. 새로운 토큰 생성
        UserResponseDto.TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

        // 5. RefreshToken Redis 업데이트
        redisTemplate.opsForValue().set("RT:" + authentication.getName(), tokenInfo.getRefreshToken(), tokenInfo.getRefreshTokenExpirationTime(), TimeUnit.MILLISECONDS);

        return response.success(tokenInfo, "Token 정보가 갱신되었습니다.", HttpStatus.OK);
    }

     */


    public ResponseEntity<?> logout(UserRequestDto.Logout logout) {
        // 1. Access Token 검증
        if (!jwtTokenProvider.validateToken(logout.getAccessToken())) {
            return response.fail("잘못된 요청입니다.", HttpStatus.BAD_REQUEST);
        }

        // 2. Access Token 에서 User email 을 가져옵니다.
        Authentication authentication = jwtTokenProvider.getAuthentication(logout.getAccessToken());

        // 3. Redis 에서 해당 User email 로 저장된 Refresh Token 이 있는지 여부를 확인 후 있을 경우 삭제합니다.
        if (redisTemplate.opsForValue().get("RT:" + authentication.getName()) != null) {
            // Refresh Token 삭제
            redisTemplate.delete("RT:" + authentication.getName());
        }

        // 4. 해당 Access Token 유효시간 가지고 와서 BlackList 로 저장하기
        Long expiration = jwtTokenProvider.getExpiration(logout.getAccessToken());
        redisTemplate.opsForValue().set(logout.getAccessToken(), "logout", expiration, TimeUnit.MILLISECONDS);

        return response.success("로그아웃 되었습니다.");
    }
    /*
    public ResponseEntity<?> authority() {
        // SecurityContext에 담겨 있는 authentication userEamil 정보
        String userEmail = SecurityUtil.getCurrentUserEmail();

        Users user = userRepository.findByuserId(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("No authentication information."));

        return response.success();
    }


    public ResponseEntity<?> authenticationTest(UserRequestDto.Reissue auth){
        if((jwtTokenProvider.getExpiration(auth.getAccessToken()) <= 0.0) && (jwtTokenProvider.getExpiration(auth.getRefreshToken()) <= 0.0))
            return response.success("로그인을 다시 해주세요.");
        else if ((jwtTokenProvider.getExpiration(auth.getAccessToken()) > 0.0) && (jwtTokenProvider.getExpiration(auth.getRefreshToken()) <= 0.0)) {
            return response.success("로그인을 다시 해주세요.");
        } else if ((jwtTokenProvider.getExpiration(auth.getAccessToken()) <= 0.0) && (jwtTokenProvider.getExpiration(auth.getRefreshToken()) > 0.0)) {
            //access token 재발급
            reissue(auth);
            return response.success("Access Token 재발급");
        }

        return response.success("Success");
    }
    */
}
