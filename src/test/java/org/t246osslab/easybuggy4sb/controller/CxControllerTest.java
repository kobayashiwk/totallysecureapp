package org.t246osslab.easybuggy4sb.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for CxController focusing on the command injection fix (CWE-77).
 *
 * The vulnerable version passed the user-supplied {cmd} path variable directly
 * to Runtime.getRuntime().exec(cmd), allowing shell metacharacter injection.
 *
 * The fix:
 *  1. Validates {cmd} against an explicit allowlist (whoami, hostname, date, uptime).
 *  2. Executes only via ProcessBuilder(cmd) — no shell is invoked, so metacharacters
 *     cannot be exploited even if the allowlist were somehow bypassed.
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CxController.class)
public class CxControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Allowlisted commands — these should be accepted (HTTP 200)
    // -------------------------------------------------------------------------

    @Test
    public void runCommand_whoami_isAccepted() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami"))
                .andExpect(status().isOk());
    }

    @Test
    public void runCommand_hostname_isAccepted() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/hostname"))
                .andExpect(status().isOk());
    }

    @Test
    public void runCommand_date_isAccepted() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/date"))
                .andExpect(status().isOk());
    }

    @Test
    public void runCommand_uptime_isAccepted() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/uptime"))
                .andExpect(status().isOk());
    }

    // -------------------------------------------------------------------------
    // Command injection attack vectors — all must be rejected (HTTP 400)
    // -------------------------------------------------------------------------

    /**
     * Classic semicolon injection: "whoami;id" must be rejected because the
     * composite string does not appear in the allowlist.
     */
    @Test
    public void runCommand_semicolonInjection_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami%3Bid"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Pipe injection: "whoami|cat /etc/passwd"
     */
    @Test
    public void runCommand_pipeInjection_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami%7Ccat+%2Fetc%2Fpasswd"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Backtick / subshell injection.
     */
    @Test
    public void runCommand_backtickInjection_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami%60id%60"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Newline injection (log injection / shell newline bypass).
     */
    @Test
    public void runCommand_newlineInjection_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami%0Aid"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Arbitrary OS command that is not in the allowlist.
     */
    @Test
    public void runCommand_arbitraryCommand_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/id"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Path-qualified command ("../bin/sh") must be rejected.
     */
    @Test
    public void runCommand_pathTraversal_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/..%2Fbin%2Fsh"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Absolute path to a binary ("/bin/sh") must be rejected.
     */
    @Test
    public void runCommand_absolutePath_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/%2Fbin%2Fsh"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Empty string must be rejected (not in allowlist).
     */
    @Test
    public void runCommand_emptyCommand_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/%20"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Command with extra whitespace/argument injection must be rejected.
     */
    @Test
    public void runCommand_argumentInjection_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami+-all"))
                .andExpect(status().isBadRequest());
    }

    /**
     * A command that is a valid Unix command but NOT in the allowlist.
     */
    @Test
    public void runCommand_notAllowlistedCommand_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/ls"))
                .andExpect(status().isBadRequest());
    }
}
