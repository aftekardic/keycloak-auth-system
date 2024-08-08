package com.example.demo.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class KeycloakJwtRolesConverterUtil implements Converter<Jwt, Collection<GrantedAuthority>> {
    private String CLAIM_REALM_ACCESS = "realm_access";
    private String CLAIM_RESOURCE_ACCESS = "resource_access";
    private String CLAIM_ROLES = "roles";

    @Override
    public Collection<GrantedAuthority> convert(@SuppressWarnings("null") Jwt jwt) {
        Map<String, Collection<String>> realmAccess = jwt.getClaim(CLAIM_REALM_ACCESS);

        Map<String, Map<String, Collection<String>>> resourceAccess = jwt.getClaim(CLAIM_RESOURCE_ACCESS);

        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        if (realmAccess != null && !realmAccess.isEmpty()) {
            Collection<String> realmRole = realmAccess.get(CLAIM_ROLES);
            if (realmRole != null && !realmRole.isEmpty()) {
                realmRole.forEach(r -> {
                    if (resourceAccess != null && !resourceAccess.isEmpty()) {
                        String role = String.format("%s", r).toUpperCase(Locale.ROOT);
                        grantedAuthorities.add(new SimpleGrantedAuthority(role));
                    } else {
                        grantedAuthorities.add(new SimpleGrantedAuthority(r));
                    }
                });
            }
        }
        return grantedAuthorities;
    }
}
