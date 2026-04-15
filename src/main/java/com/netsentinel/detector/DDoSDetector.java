package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Detecteur d'attaques DDoS.
 *
 * Regles :
 * - Calcul de la moyenne de requetes/seconde sur tout le fichier
 * - Alerte si une IP depasse 10x la moyenne sur une fenetre de 10 secondes
 * - Alerte CRITICAL si le volume global depasse 50x la moyenne (DDoS distribue)
 */
public class DDoSDetector implements ThreatDetector {

    private static final int WINDOW_SECONDS = 10;
    private static final double IP_THRESHOLD_MULTIPLIER = 10.0;
    private static final double GLOBAL_THRESHOLD_MULTIPLIER = 50.0;

    @Override
    public String getName() {
        return "DDOS";
    }

    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();

        if (entries.size() < 2) return alerts;

        // Calculer la duree totale et la moyenne de req/sec
        LocalDateTime first = entries.stream().map(LogEntry::getTimestamp)
                .min(Comparator.naturalOrder()).orElse(LocalDateTime.now());
        LocalDateTime last = entries.stream().map(LogEntry::getTimestamp)
                .max(Comparator.naturalOrder()).orElse(LocalDateTime.now());

        long totalSeconds = Math.max(ChronoUnit.SECONDS.between(first, last), 1);
        double avgReqPerSec = (double) entries.size() / totalSeconds;

        // Seuil par IP sur une fenetre de 10 secondes
        double ipThreshold = avgReqPerSec * IP_THRESHOLD_MULTIPLIER * WINDOW_SECONDS;

        // Detection par IP : fenetre de 10 secondes
        Map<String, List<LogEntry>> byIP = entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getIpAddress));

        for (Map.Entry<String, List<LogEntry>> entry : byIP.entrySet()) {
            String ip = entry.getKey();
            List<LogEntry> ipEntries = entry.getValue();
            ipEntries.sort(Comparator.comparing(LogEntry::getTimestamp));

            // Fenetre glissante
            Deque<LogEntry> window = new ArrayDeque<>();

            for (LogEntry log : ipEntries) {
                window.addLast(log);

                // Retirer les entrees hors fenetre
                LocalDateTime windowStart = log.getTimestamp().minusSeconds(WINDOW_SECONDS);
                while (!window.isEmpty() && window.peekFirst().getTimestamp().isBefore(windowStart)) {
                    window.pollFirst();
                }

                if (window.size() > ipThreshold && ipThreshold > 0) {
                    String desc = String.format(
                            "Volume anormal : %d requetes en %ds (moyenne globale: %.2f req/s, seuil: %.0f)",
                            window.size(), WINDOW_SECONDS, avgReqPerSec, ipThreshold
                    );

                    alerts.add(new Alert(
                            getName(), Severity.HIGH, ip, desc,
                            window.peekFirst().getTimestamp(),
                            new ArrayList<>(window)
                    ));

                    window.clear();
                }
            }
        }

        // Detection DDoS distribue : volume global sur fenetre de 10 secondes
        double globalThreshold = avgReqPerSec * GLOBAL_THRESHOLD_MULTIPLIER * WINDOW_SECONDS;
        List<LogEntry> sorted = new ArrayList<>(entries);
        sorted.sort(Comparator.comparing(LogEntry::getTimestamp));

        Deque<LogEntry> globalWindow = new ArrayDeque<>();
        for (LogEntry log : sorted) {
            globalWindow.addLast(log);

            LocalDateTime windowStart = log.getTimestamp().minusSeconds(WINDOW_SECONDS);
            while (!globalWindow.isEmpty() && globalWindow.peekFirst().getTimestamp().isBefore(windowStart)) {
                globalWindow.pollFirst();
            }

            if (globalWindow.size() > globalThreshold && globalThreshold > 0) {
                String desc = String.format(
                        "DDoS distribue : %d requetes globales en %ds (seuil: %.0f)",
                        globalWindow.size(), WINDOW_SECONDS, globalThreshold
                );

                alerts.add(new Alert(
                        getName(), Severity.CRITICAL, "MULTIPLE",
                        desc, globalWindow.peekFirst().getTimestamp(),
                        new ArrayList<>(globalWindow)
                ));

                globalWindow.clear();
            }
        }

        return alerts;
    }
}
