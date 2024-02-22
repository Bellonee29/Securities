package com.wayTech.SecurityJWT.demo;

import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo-controller")
@RequiredArgsConstructor
public class DemoController {
    @GetMapping()
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello guy, This is a secure endpoint");
    }
}