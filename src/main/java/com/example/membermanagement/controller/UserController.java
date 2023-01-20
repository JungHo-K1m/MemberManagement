package com.example.membermanagement.controller;

import antlr.StringUtils;
import com.example.membermanagement.dto.Response;
import com.example.membermanagement.dto.request.UserRequestDto;
import com.example.membermanagement.lib.Helper;
import com.example.membermanagement.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final Response response;


    @PostMapping("/signup")
    public ResponseEntity<?> createUser(@Validated @RequestBody UserRequestDto.SignUp signUp, Errors errors) throws NoSuchAlgorithmException {
        if (errors.hasErrors()) {
            return response.invalidFields(Helper.refineErrors(errors));
        }
        return userService.insertUser(signUp);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Validated @RequestBody UserRequestDto.Login login, Errors errors) throws NoSuchAlgorithmException {
        if (errors.hasErrors()) {
            return response.invalidFields(Helper.refineErrors(errors));
        }
        return userService.login(login);
    }


    @GetMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("authorization") String accessToken) {

        String[] result = accessToken.split(" ");       //Bearer 텍스트 분리
        System.out.println(Arrays.toString(result));
        String ac = result[1];                              //accessToken만 따로 저장

        return userService.logout(ac);

        /*
        if (errors.hasErrors()) {
            return response.invalidFields(Helper.refineErrors(errors));
        }
        return userService.logout(logout);

         */
    }

    /*
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@Validated UserRequestDto.Reissue reissue, Errors errors){
        if(errors.hasErrors()){
            return response.invalidFields(Helper.refineErrors(errors));
        }
        return userService.reissue(reissue);
    }

     */
    /*
    @GetMapping("/authority")
    public ResponseEntity<?> authority() {
        log.info("ADD ROLE_ADMIN");
        return userService.authority();
    }

    @RequestMapping("/test")
    public ResponseEntity<?> authenticationTest( UserRequestDto.Reissue auth, Errors errors){
        if (errors.hasErrors()) {
            return response.invalidFields(Helper.refineErrors(errors));
        }
        return userService.authenticationTest(auth);
    }

 */

}