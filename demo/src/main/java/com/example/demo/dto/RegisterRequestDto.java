package com.example.demo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterRequestDto {
    private String email;
    private String password;
    private String firstName;
    private String lastName;
}