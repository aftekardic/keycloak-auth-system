package com.example.demo.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class SessionStorageUtil {
    private final Map<String, Map<String, String>> storage = new ConcurrentHashMap<>();

    public void putCache(String cacheName, String key, String value, long ttl) {
        Map<String, String> cache = storage.computeIfAbsent(cacheName, k -> new ConcurrentHashMap<>());
        cache.put(key, value);
    }

    public String getCache(String cacheName, String key) {
        Map<String, String> cache = storage.get(cacheName);
        return cache != null ? cache.get(key) : null;
    }

    public void removeCache(String cacheName, String key) {
        Map<String, String> cache = storage.get(cacheName);
        if (cache != null) {
            cache.remove(key);
        }
    }
}
