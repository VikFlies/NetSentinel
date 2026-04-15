package com.netsentinel.analyzer;

import com.netsentinel.model.LogEntry;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Dashboard textuel affichant les statistiques des logs.
 *
 * Affiche :
 * 1. Nombre total de requetes parsees
 * 2. Top 10 des IPs les plus actives
 * 3. Distribution des codes HTTP (200, 301, 401, 403, 404, 500...)
 * 4. Top 10 des URLs les plus accedees
 * 5. Top 5 des user-agents
 */
public class DashboardAnalyzer {

    private final List<LogEntry> entries;

    public DashboardAnalyzer(List<LogEntry> entries) {
        this.entries = entries;
    }

    /**
     * Affiche le dashboard complet dans la console.
     */
    public void printDashboard() {
        printSeparator("DASHBOARD NETSENTINEL");

        // 1. Nombre total de requetes
        System.out.println("\n  Nombre total de requetes parsees : " + entries.size());
        System.out.println("  IPs uniques : " + getUniqueIPCount());
        System.out.println("  Periode : " + getTimePeriod());

        // 2. Top 10 IPs
        printSeparator("TOP 10 DES IPS LES PLUS ACTIVES");
        printRanking(getTopIPs(10));

        // 3. Distribution codes HTTP
        printSeparator("DISTRIBUTION DES CODES HTTP");
        printDistribution(getStatusCodeDistribution());

        // 4. Top 10 URLs
        printSeparator("TOP 10 DES URLS LES PLUS ACCEDEES");
        printRanking(getTopURLs(10));

        // 5. Top 5 User-Agents
        printSeparator("TOP 5 DES USER-AGENTS");
        printRanking(getTopUserAgents(5));

        printSeparator("FIN DU DASHBOARD");
    }

    // ====== Calculs ======

    public long getUniqueIPCount() {
        return entries.stream().map(LogEntry::getIpAddress).distinct().count();
    }

    public String getTimePeriod() {
        if (entries.isEmpty()) return "N/A";
        var min = entries.stream().map(LogEntry::getTimestamp).min(Comparator.naturalOrder());
        var max = entries.stream().map(LogEntry::getTimestamp).max(Comparator.naturalOrder());
        return min.get() + "  ->  " + max.get();
    }

    public LinkedHashMap<String, Long> getTopIPs(int limit) {
        return entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getIpAddress, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(limit)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    public LinkedHashMap<Integer, Long> getStatusCodeDistribution() {
        return entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getStatusCode, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<Integer, Long>comparingByValue().reversed())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    public LinkedHashMap<String, Long> getTopURLs(int limit) {
        return entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getUrl, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(limit)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    public LinkedHashMap<String, Long> getTopUserAgents(int limit) {
        return entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getUserAgent, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(limit)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    // ====== Affichage ======

    private void printSeparator(String title) {
        System.out.println("\n" + "=".repeat(70));
        System.out.printf("  %s%n", title);
        System.out.println("=".repeat(70));
    }

    private <K> void printRanking(LinkedHashMap<K, Long> map) {
        int rank = 1;
        for (Map.Entry<K, Long> entry : map.entrySet()) {
            String key = entry.getKey().toString();
            if (key.length() > 60) key = key.substring(0, 57) + "...";
            System.out.printf("  %2d. %-62s %5d%n", rank++, key, entry.getValue());
        }
    }

    private void printDistribution(LinkedHashMap<Integer, Long> map) {
        long total = entries.size();
        for (Map.Entry<Integer, Long> entry : map.entrySet()) {
            double pct = (double) entry.getValue() / total * 100;
            int barLen = (int) (pct / 2);
            String bar = "#".repeat(Math.max(barLen, 1));
            System.out.printf("  HTTP %d : %5d (%5.1f%%) %s%n",
                    entry.getKey(), entry.getValue(), pct, bar);
        }
    }
}
