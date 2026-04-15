package com.netsentinel;

import com.netsentinel.detector.*;
import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.parser.LogParser;
import com.netsentinel.whitelist.WhitelistManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires NetSentinel (minimum 5 requis).
 *
 * Test 1 : Parsing correct d'une ligne de log
 * Test 2 : 15 requetes 401 en 2 min => alerte brute-force
 * Test 3 : URL contenant "' OR 1=1" => alerte SQL injection
 * Test 4 : IP whitelistee ne genere pas d'alerte
 * Test 5 : Correlation augmente la severite
 * Test 6 : Detection de scanner (user-agent sqlmap)
 * Test 7 : Parsing echoue sur ligne invalide
 */
public class NetSentinelTest {

    private LogParser parser;

    @BeforeEach
    void setUp() {
        parser = new LogParser();
    }

    // ====== Test 1 : Parsing correct d'une ligne de log ======
    @Test
    void testParsingCorrectLigneDuLog() {
        String line = "192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";

        LogEntry entry = parser.parseLine(line);

        assertNotNull(entry, "L'entree ne devrait pas etre null");
        assertEquals("192.168.1.45", entry.getIpAddress());
        assertEquals("GET", entry.getMethod());
        assertEquals("/index.html", entry.getUrl());
        assertEquals("HTTP/1.1", entry.getProtocol());
        assertEquals(200, entry.getStatusCode());
        assertEquals(5423, entry.getResponseSize());
        assertEquals("Mozilla/5.0", entry.getUserAgent());
        assertEquals(2025, entry.getTimestamp().getYear());
        assertEquals(15, entry.getTimestamp().getDayOfMonth());
        assertEquals(10, entry.getTimestamp().getHour());
        assertEquals(23, entry.getTimestamp().getMinute());
        assertEquals(45, entry.getTimestamp().getSecond());
    }

    // ====== Test 2 : 15 requetes 401 en 2 min => alerte brute-force ======
    @Test
    void testBruteForceDetection() {
        List<LogEntry> entries = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.of(2025, 3, 15, 10, 0, 0);

        // Generer 15 requetes 401 depuis la meme IP en 2 minutes
        for (int i = 0; i < 15; i++) {
            entries.add(new LogEntry(
                    "10.0.0.99", "-", baseTime.plusSeconds(i * 8), // ~8s d'ecart, total 2 min
                    "POST", "/login", "HTTP/1.1",
                    401, 287, "-", "curl/7.68",
                    "fake line"
            ));
        }

        BruteForceDetector detector = new BruteForceDetector();
        List<Alert> alerts = detector.detect(entries);

        assertFalse(alerts.isEmpty(), "Le detecteur brute-force devrait generer au moins une alerte");
        assertEquals("BRUTE_FORCE", alerts.get(0).getType());
        assertEquals("10.0.0.99", alerts.get(0).getIpAddress());
        assertTrue(alerts.get(0).getSeverity() == Severity.MEDIUM || alerts.get(0).getSeverity() == Severity.HIGH);
    }

    // ====== Test 3 : URL contenant "' OR 1=1" => alerte SQL injection ======
    @Test
    void testSqlInjectionDetection() {
        List<LogEntry> entries = List.of(
                new LogEntry(
                        "203.0.113.50", "-",
                        LocalDateTime.of(2025, 3, 15, 10, 24, 15),
                        "GET", "/search?q=' OR 1=1--", "HTTP/1.1",
                        200, 0, "-", "sqlmap/1.5",
                        "fake line"
                )
        );

        SqlInjectionDetector detector = new SqlInjectionDetector();
        List<Alert> alerts = detector.detect(entries);

        assertFalse(alerts.isEmpty(), "Le detecteur SQL injection devrait generer une alerte");
        assertEquals("SQL_INJECTION", alerts.get(0).getType());
        assertEquals("203.0.113.50", alerts.get(0).getIpAddress());
    }

    // ====== Test 4 : IP whitelistee ne genere pas d'alerte ======
    @Test
    void testWhitelistFiltersAlerts() {
        WhitelistManager wl = new WhitelistManager();
        // Ajouter une IP manuellement (sans fichier)
        wl.getWhitelistedIPs().add("192.168.1.1");

        List<Alert> alerts = new ArrayList<>();
        alerts.add(new Alert(
                "SQL_INJECTION", Severity.HIGH, "192.168.1.1",
                "Test injection", LocalDateTime.now(), List.of()
        ));
        alerts.add(new Alert(
                "BRUTE_FORCE", Severity.MEDIUM, "10.0.0.99",
                "Test brute force", LocalDateTime.now(), List.of()
        ));

        List<Alert> filtered = wl.filterAlerts(alerts);

        assertEquals(1, filtered.size(), "Seule l'alerte de l'IP non whitelistee devrait rester");
        assertEquals("10.0.0.99", filtered.get(0).getIpAddress());
    }

    // ====== Test 5 : Correlation augmente la severite ======
    @Test
    void testCorrelationAugmenteSeverite() {
        List<Alert> alerts = new ArrayList<>();

        // IP avec 2 detecteurs differents
        alerts.add(new Alert(
                "SQL_INJECTION", Severity.MEDIUM, "10.0.0.50",
                "SQL detected", LocalDateTime.now(), List.of()
        ));
        alerts.add(new Alert(
                "SCAN", Severity.MEDIUM, "10.0.0.50",
                "Scan detected", LocalDateTime.now(), List.of()
        ));

        AlertCorrelator correlator = new AlertCorrelator();
        List<Alert> correlated = correlator.correlate(alerts);

        // 2 detecteurs => severite +1 : MEDIUM -> HIGH
        for (Alert a : correlated) {
            assertEquals(Severity.HIGH, a.getSeverity(),
                    "Avec 2 detecteurs, la severite devrait passer de MEDIUM a HIGH");
        }

        // Tester avec 3 detecteurs => CRITICAL
        alerts.add(new Alert(
                "BRUTE_FORCE", Severity.LOW, "10.0.0.50",
                "Brute force detected", LocalDateTime.now(), List.of()
        ));

        List<Alert> correlated2 = correlator.correlate(alerts);
        for (Alert a : correlated2) {
            assertEquals(Severity.CRITICAL, a.getSeverity(),
                    "Avec 3+ detecteurs, la severite devrait etre CRITICAL");
        }
    }

    // ====== Test 6 : Detection de scanner par user-agent ======
    @Test
    void testScannerDetectionByUserAgent() {
        List<LogEntry> entries = List.of(
                new LogEntry(
                        "91.240.118.50", "-",
                        LocalDateTime.of(2025, 3, 16, 11, 0, 0),
                        "GET", "/.htpasswd", "HTTP/1.1",
                        404, 563, "-", "nikto/2.5.0",
                        "fake line"
                )
        );

        ScanDetector detector = new ScanDetector();
        List<Alert> alerts = detector.detect(entries);

        assertFalse(alerts.isEmpty(), "Le detecteur de scan devrait generer une alerte");
        boolean hasScanner = alerts.stream().anyMatch(a ->
                a.getDescription().contains("nikto") || a.getDescription().contains("Outil de scan"));
        assertTrue(hasScanner, "L'alerte devrait mentionner l'outil nikto");
    }

    // ====== Test 7 : Parsing echoue sur ligne invalide ======
    @Test
    void testParsingLigneInvalide() {
        String invalidLine = "ceci n'est pas une ligne de log valide";
        LogEntry entry = parser.parseLine(invalidLine);
        assertNull(entry, "Le parseur devrait retourner null pour une ligne invalide");

        String emptyLine = "";
        LogEntry entry2 = parser.parseLine(emptyLine);
        assertNull(entry2, "Le parseur devrait retourner null pour une ligne vide");
    }
}
