package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Detecteur de scans de vulnerabilites.
 *
 * Regles :
 * - Requetes vers des chemins typiques : /admin, /wp-login.php, /.env, /phpmyadmin,
 *   /config.yml, /.git/config, /backup.sql
 * - Detection par user-agent : sqlmap, nikto, nmap, dirbuster, gobuster
 * - Plus de 20 URLs differentes en 404 depuis une meme IP = scan de repertoires
 */
public class ScanDetector implements ThreatDetector {

    // Chemins suspects
    private static final List<Pattern> SUSPICIOUS_PATHS = List.of(
            Pattern.compile("(?i)/admin"),
            Pattern.compile("(?i)/wp-login\\.php"),
            Pattern.compile("(?i)/wp-admin"),
            Pattern.compile("(?i)/wp-content"),
            Pattern.compile("(?i)/wp-includes"),
            Pattern.compile("(?i)/\\.env"),
            Pattern.compile("(?i)/phpmyadmin"),
            Pattern.compile("(?i)/config\\.yml"),
            Pattern.compile("(?i)/\\.git"),
            Pattern.compile("(?i)/backup\\.sql"),
            Pattern.compile("(?i)/\\.htpasswd"),
            Pattern.compile("(?i)/\\.htaccess"),
            Pattern.compile("(?i)/cgi-bin"),
            Pattern.compile("(?i)/jmx-console"),
            Pattern.compile("(?i)/manager/html"),
            Pattern.compile("(?i)/webshell"),
            Pattern.compile("(?i)/shell\\.php"),
            Pattern.compile("(?i)/administrator")
    );

    // User-agents d'outils de scan
    private static final List<Pattern> SCANNER_AGENTS = List.of(
            Pattern.compile("(?i)sqlmap"),
            Pattern.compile("(?i)nikto"),
            Pattern.compile("(?i)nmap"),
            Pattern.compile("(?i)dirbuster"),
            Pattern.compile("(?i)gobuster"),
            Pattern.compile("(?i)wpscan"),
            Pattern.compile("(?i)hydra"),
            Pattern.compile("(?i)acunetix"),
            Pattern.compile("(?i)nessus"),
            Pattern.compile("(?i)masscan"),
            Pattern.compile("(?i)burpsuite")
    );

    private static final int DIR_SCAN_THRESHOLD = 20;

    @Override
    public String getName() {
        return "SCAN";
    }

    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();

        // 1. Detection par chemin suspect
        for (LogEntry entry : entries) {
            for (Pattern p : SUSPICIOUS_PATHS) {
                if (p.matcher(entry.getUrl()).find()) {
                    alerts.add(new Alert(
                            getName(), Severity.MEDIUM, entry.getIpAddress(),
                            "Acces a un chemin suspect : " + entry.getUrl(),
                            entry.getTimestamp(), List.of(entry)
                    ));
                    break; // Un seul alert par entree pour les chemins
                }
            }
        }

        // 2. Detection par user-agent (outils de scan)
        for (LogEntry entry : entries) {
            for (Pattern p : SCANNER_AGENTS) {
                if (p.matcher(entry.getUserAgent()).find()) {
                    alerts.add(new Alert(
                            getName(), Severity.HIGH, entry.getIpAddress(),
                            "Outil de scan detecte : " + entry.getUserAgent(),
                            entry.getTimestamp(), List.of(entry)
                    ));
                    break;
                }
            }
        }

        // 3. Scan de repertoires : > 20 URLs en 404 depuis une meme IP
        Map<String, List<LogEntry>> notFoundByIP = entries.stream()
                .filter(e -> e.getStatusCode() == 404)
                .collect(Collectors.groupingBy(LogEntry::getIpAddress));

        for (Map.Entry<String, List<LogEntry>> entry : notFoundByIP.entrySet()) {
            String ip = entry.getKey();
            List<LogEntry> notFoundEntries = entry.getValue();

            long uniqueURLs = notFoundEntries.stream()
                    .map(LogEntry::getUrl).distinct().count();

            if (uniqueURLs > DIR_SCAN_THRESHOLD) {
                String desc = String.format(
                        "Scan de repertoires : %d URLs differentes en 404", uniqueURLs
                );
                alerts.add(new Alert(
                        getName(), Severity.HIGH, ip, desc,
                        notFoundEntries.get(0).getTimestamp(),
                        notFoundEntries
                ));
            }
        }

        return alerts;
    }
}
