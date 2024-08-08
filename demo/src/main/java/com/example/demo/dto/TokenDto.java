package com.example.demo.dto;

import lombok.Data;

@Data
public class TokenDto {
    private String access_token;
    private String refresh_token;
    private int expires_in;
    private int refresh_expires_in;
}
