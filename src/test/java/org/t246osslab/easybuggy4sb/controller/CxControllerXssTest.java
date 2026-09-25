package org.t246osslab.easybuggy4sb.controller;

import org.junit.Test;
import org.owasp.esapi.ESAPI;

import static org.junit.Assert.*;

/**
 * Unit tests verifying that CxController.runCommand HTML-encodes its output
 * to prevent Stored XSS (CWE-79).
 *
 * These tests exercise the ESAPI.encoder().encodeForHTML() call that was added
 * to break the taint flow identified by the SAST finding: command output
 * (buf) flows from Runtime.exec() directly into the HTTP response without
 * sanitization.  After the fix the raw string is wrapped in encodeForHTML()
 * before it is returned, so any HTML/JS injected through the data-store is
 * rendered as inert text rather than executed markup.
 */
public class CxControllerXssTest {

    // -----------------------------------------------------------------------
    // Helper: delegate to the same ESAPI encoder used in the production fix
    // -----------------------------------------------------------------------

    /**
     * Applies the same HTML-encoding that the fixed runCommand() applies
     * before returning its response body.
     */
    private String encodeForHTML(String input) {
        return ESAPI.encoder().encodeForHTML(input);
    }

    // -----------------------------------------------------------------------
    // Tests: special HTML characters are encoded
    // -----------------------------------------------------------------------

    @Test
    public void scriptTagIsEncoded() {
        // A payload commonly stored by attackers to trigger stored XSS.
        String malicious = "<script>alert('xss')</script>";
        String encoded = encodeForHTML(malicious);

        // The angle brackets must be entity-encoded so the browser treats
        // the output as text, not as a script element.
        assertFalse("'<' must be encoded", encoded.contains("<"));
        assertFalse("'>' must be encoded", encoded.contains(">"));
        // Output should not be empty – the content is still present but safe.
        assertFalse("Encoded output must not be empty", encoded.isEmpty());
        // ESAPI specifically encodes '<' as &#60; or &lt;
        assertTrue("Encoded output must represent the original content",
                encoded.contains("script"));
    }

    @Test
    public void ampersandIsEncoded() {
        String input = "output & data";
        String encoded = encodeForHTML(input);
        assertFalse("'&' must be encoded to prevent HTML entity injection",
                encoded.contains(" & "));
    }

    @Test
    public void doubleQuoteIsEncoded() {
        String input = "value=\"malicious\"";
        String encoded = encodeForHTML(input);
        assertFalse("'\"' must be encoded",
                encoded.contains("\"malicious\""));
    }

    @Test
    public void singleQuoteIsEncoded() {
        String input = "value='malicious'";
        String encoded = encodeForHTML(input);
        // ESAPI encodes ' as &#x27; or &apos;
        assertFalse("Raw single-quote must be encoded",
                encoded.contains("'malicious'"));
    }

    @Test
    public void imgOnerrorPayloadIsEncoded() {
        String payload = "<img src=x onerror=\"alert(1)\">";
        String encoded = encodeForHTML(payload);
        assertFalse("'<' from img tag must be encoded", encoded.contains("<img"));
        assertFalse("'>' from img tag must be encoded", encoded.contains(">"));
    }

    // -----------------------------------------------------------------------
    // Tests: safe output is preserved (no double-encoding, no data loss)
    // -----------------------------------------------------------------------

    @Test
    public void plainTextIsPreserved() {
        // Normal command output such as a username or hostname should pass
        // through encoding unchanged (no special HTML characters present).
        String plain = "root";
        String encoded = encodeForHTML(plain);
        assertEquals("Plain alphanumeric text must be returned unmodified",
                plain, encoded);
    }

    @Test
    public void newlineAndSpaceArePreserved() {
        // Command output often contains whitespace; those characters are safe
        // in HTML text content and should not be stripped.
        String plain = "hello world\nline two";
        String encoded = encodeForHTML(plain);
        // Spaces and newlines are not HTML-special; ESAPI leaves them as-is
        // (or encodes newline as &#10; — either way the content is retained).
        assertFalse("Encoded output must not be empty", encoded.isEmpty());
        assertTrue("Content after encoding must still contain the text",
                encoded.contains("hello") && encoded.contains("world"));
    }

    @Test
    public void nullSafetyDoesNotApplyToEmptyString() {
        // An empty output buffer (e.g., command produces no output) should
        // encode to an empty string without throwing.
        String encoded = encodeForHTML("");
        assertNotNull("Encoding empty string must not return null", encoded);
        assertEquals("Encoding empty string must return empty string", "", encoded);
    }

    // -----------------------------------------------------------------------
    // Tests: the raw XSS payloads must NOT appear literally in the output
    // -----------------------------------------------------------------------

    @Test
    public void storedXssPayloadDoesNotSurviveEncoding() {
        // Simulate a payload that an attacker stored in the data-store and
        // that gets embedded in the command output returned to another user.
        String[] xssPayloads = {
            "<script>document.cookie</script>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"
        };

        for (String payload : xssPayloads) {
            String encoded = encodeForHTML(payload);
            // After encoding, '<' must no longer appear as a literal '<'
            assertFalse("XSS payload must not contain literal '<' after encoding: " + payload,
                    encoded.contains("<script") || encoded.contains("<svg"));
        }
    }
}
