package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Detecteur de tentatives de brute-force.
 *
 * Regle : plus de 10 reponses 401 ou 403 depuis une meme IP en moins de 5 minutes.
 * Severite : HIGH si > 50 tentatives, MEDIUM si > 10.
 */
public class BruteForceDetector implements ThreatDetector {

    private static final int THRESHOLD_MEDIUM = 10;
    private static final int THRESHOLD_HIGH = 50;
    private static final Duration WINDOW = Duration.ofMinutes(5);

    @Override
    public String getName() {
        return "BRUTE_FORCE";
    }

    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();

        // Grouper par IP les requetes avec code 401 ou 403
        Map<String, List<LogEntry>> failedByIP = entries.stream()
                .filter(e -> e.getStatusCode() == 401 || e.getStatusCode() == 403)
                .collect(Collectors.groupingBy(LogEntry::getIpAddress));

        for (Map.Entry<String, List<LogEntry>> entry : failedByIP.entrySet()) {
            String ip = entry.getKey();
            List<LogEntry> failed = entry.getValue();

            // Trier par timestamp
            failed.sort(Comparator.comparing(LogEntry::getTimestamp));

            // Fenetre glissante de 5 minutes
            List<LogEntry> window = new ArrayList<>();

            for (LogEntry log : failed) {
                window.add(log);

                // Retirer les entrees hors de la fenetre
                LocalDateTime windowStart = log.getTimestamp().minus(WINDOW);
                window.removeIf(e -> e.getTimestamp().isBefore(windowStart));

                // Verifier le seuil
                if (window.size() > THRESHOLD_MEDIUM) {
                    Severity sev = window.size() > THRESHOLD_HIGH ? Severity.HIGH : Severity.MEDIUM;

                    String desc = String.format(
                            "%d tentatives echouees (401/403) en moins de 5 minutes",
                            window.size()
                    );

                    alerts.add(new Alert(
                            getName(), sev, ip, desc,
                            window.get(0).getTimestamp(),
                            new ArrayList<>(window)
                    ));

                    // Vider la fenetre pour eviter les doublons
                    window.clear();
                }
            }
        }

        return alerts;
    }
}
