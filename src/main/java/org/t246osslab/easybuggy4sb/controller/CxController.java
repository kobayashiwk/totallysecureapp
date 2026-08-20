package org.t246osslab.easybuggy4sb.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class CxController {

    private static final Map<String, List<String>> ALLOWED_COMMANDS;

    static {
        Map<String, List<String>> commands = new HashMap<>();
        commands.put("whoami", Collections.singletonList("whoami"));
        commands.put("hostname", Collections.singletonList("hostname"));
        commands.put("uptime", Collections.singletonList("uptime"));
        ALLOWED_COMMANDS = Collections.unmodifiableMap(commands);
    }

    @GetMapping("v2/authed/getTime") // require auth
    public String getTime() {
        return new Date().toString();
    }

    @GetMapping("v2/authed/getUser") // require auth
    public String getUser() {
        return "user is: " + System.getProperty("user.name");
    }

    @GetMapping("v2/authed/getIP") // require auth
    public String getIP() throws UnknownHostException {
        return Inet4Address.getLocalHost().getHostAddress();
    }

    @ApiIgnore // don't want this in openapi file
    @GetMapping("v2/authed/multiply") // require auth
    public int multiply(@RequestParam(name = "a") int a, @RequestParam(name = "b") int b) {
        return a * b;
    }

    // curl -u user:pass -X POST localhost:8080/v2/authed/legacy/runCommand/whoami
    @PostMapping("v2/authed/legacy/runCommand/{cmd}")
    public ResponseEntity<String> runCommand(@PathVariable String cmd) throws IOException {
        List<String> command = ALLOWED_COMMANDS.get(cmd);
        if (command == null) {
            return ResponseEntity.badRequest()
                    .body("Unsupported command. Allowed commands: " + ALLOWED_COMMANDS.keySet());
        }
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        try (InputStream in = process.getInputStream()) {
            byte[] buf = new byte[1024];
            int len = in.read(buf);
            if (len < 0) {
                return new ResponseEntity<>("", HttpStatus.OK);
            }
            return ResponseEntity.ok(new String(buf, 0, len, StandardCharsets.UTF_8));
        } finally {
            process.destroy();
        }
    }

    @GetMapping("legacy/add")
    public int add(@RequestParam(name = "a") int a, @RequestParam(name = "b") int b) {
        return a + b;
    }

    @GetMapping("internal")
    public String internal() {
        return "this is an internal api";
    }

    @GetMapping("internal/op1")
    public String op1() {
        return "op1 api";
    }

    @PostMapping("internal/op2")
    public String op2() {
        return "op2 api";
    }
}
