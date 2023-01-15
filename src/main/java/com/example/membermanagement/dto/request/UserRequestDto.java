package com.example.membermanagement.dto.request;

import com.example.membermanagement.jwt.SHA256;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import java.security.NoSuchAlgorithmException;

public class UserRequestDto {
    @Getter
    @Setter
    public static class SignUp {


        @NotEmpty(message = "ID는 필수 입력값입니다.")
        private String userId;

        @NotEmpty(message = "이메일은 필수 입력값입니다.")
        @Email(message = "이메일 형식에 맞지 않습니다.")
        private String userEmail;

        @NotEmpty(message = "비밀번호는 필수 입력값입니다.")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[~!@#$%^&*()+|=])[A-Za-z\\d~!@#$%^&*()+|=]{8,16}$", message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용하세요.")
        private String userPw;
    }

    @Getter
    @Setter
    public static class Login {
        @NotEmpty(message = "ID는 필수 입력값입니다.")
        private String userId;

        @NotEmpty(message = "비밀번호는 필수 입력값입니다.")
        private String userPw;


        public UsernamePasswordAuthenticationToken toAuthentication() throws NoSuchAlgorithmException {
            SHA256 sha256 = new SHA256();
            System.out.println("encoding PW : " + getUserPw());
            String enPW = sha256.encrypt(sha256.encrypt(getUserPw()));
            return new UsernamePasswordAuthenticationToken(userId, enPW);
        }
    }

    @Getter
    @Setter
    public static class Reissue {
        @NotEmpty(message = "accessToken 을 입력해주세요.")
        private String accessToken;

        @NotEmpty(message = "refreshToken 을 입력해주세요.")
        private String refreshToken;
    }

    @Getter
    @Setter
    public static class Logout {
        @NotEmpty(message = "잘못된 요청입니다.")
        private String accessToken;

        @NotEmpty(message = "잘못된 요청입니다.")
        private String refreshToken;
    }
}
