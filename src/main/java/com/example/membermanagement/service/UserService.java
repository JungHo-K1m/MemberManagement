package com.example.membermanagement.service;

import com.example.membermanagement.dto.Response;
import com.example.membermanagement.dto.request.UserRequestDto;
import com.example.membermanagement.dto.response.UserResponseDto;
import com.example.membermanagement.entity.Role;
import com.example.membermanagement.entity.User;
import com.example.membermanagement.jwt.JwtTokenProvider;
import com.example.membermanagement.jwt.SHA256;
import com.example.membermanagement.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@Transactional
@AllArgsConstructor
public class UserService implements UserDetailsService {


    private final UserRepository userRepository;
    private final Response response;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisTemplate redisTemplate;

    public ResponseEntity<?> insertUser(UserRequestDto.SignUp signUp) throws NoSuchAlgorithmException {

        Optional<User> byId = userRepository.findByuserId(signUp.getUserId());
        if(byId.isPresent())
            return null;

        User user = new User();
        user.setUserId(signUp.getUserId());
        user.setUserEmail(signUp.getUserEmail());
        SHA256 sha256 = new SHA256();                                       //sha256 암호화
        user.setUserPw(sha256.encrypt(sha256.encrypt(signUp.getUserPw()))); //sha256암호화 2번 돌린 비밀번호를 저장.
        user.setUserRole(Role.USER);
        userRepository.save(user);

        return response.success("회원가입에 성공하였습니다.");
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return (UserDetails) Optional
                .ofNullable(userRepository.findByuserId(username).orElse(null))
                .orElseThrow(()-> new BadCredentialsException("등록되지 않음"));
    }
    public ResponseEntity<?> login(UserRequestDto.Login login) throws NoSuchAlgorithmException {
        System.out.println("로그인 시도");

        if (userRepository.findByuserId(login.getUserId()).orElse(null) == null) {
            return response.fail("해당하는 유저가 존재하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = login.toAuthentication();

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        System.out.println("토큰 생성");
        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        UserResponseDto.TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

        // 4. RefreshToken Redis 저장 (expirationTime 설정을 통해 자동 삭제 처리)
        redisTemplate.opsForValue().set("RT:" + authentication.getName(), tokenInfo.getRefreshToken(), tokenInfo.getRefreshTokenExpirationTime(), TimeUnit.MILLISECONDS);

        return response.success(tokenInfo, "로그인에 성공했습니다.", HttpStatus.OK);
    }


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
}
