package com.netsentinel.report;

import com.netsentinel.model.Alert;
import com.netsentinel.model.Severity;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Generateur de rapport de securite et de regles de blocage.
 *
 * Genere :
 * - rapport_securite.txt : resume executif, timeline, detail par IP, recommandations
 * - Regles iptables et .htaccess pour les IPs HIGH/CRITICAL
 */
public class ReportGenerator {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Genere le rapport complet dans rapport_securite.txt.
     */
    public void generateReport(List<Alert> alerts, String outputPath) throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(outputPath))) {

            out.println("=".repeat(80));
            out.println("                     RAPPORT DE SECURITE NETSENTINEL");
            out.println("                  Genere le " + LocalDateTime.now().format(FMT));
            out.println("=".repeat(80));

            // 1. Resume executif
            writeExecutiveSummary(out, alerts);

            // 2. Timeline des incidents
            writeTimeline(out, alerts);

            // 3. Detail par IP suspecte
            writeDetailByIP(out, alerts);

            // 4. Regles de blocage
            writeBlockingRules(out, alerts);

            // 5. Recommandations
            writeRecommendations(out, alerts);

            out.println("\n" + "=".repeat(80));
            out.println("                         FIN DU RAPPORT");
            out.println("=".repeat(80));
        }
    }

    /**
     * 1. Resume executif : nombre d'alertes par severite, IPs les plus dangereuses.
     */
    private void writeExecutiveSummary(PrintWriter out, List<Alert> alerts) {
        out.println("\n" + "-".repeat(80));
        out.println("1. RESUME EXECUTIF");
        out.println("-".repeat(80));

        out.println("\n  Nombre total d'alertes : " + alerts.size());

        // Par severite
        Map<Severity, Long> bySeverity = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getSeverity, Collectors.counting()));

        out.println("\n  Alertes par severite :");
        for (Severity sev : Severity.values()) {
            long count = bySeverity.getOrDefault(sev, 0L);
            if (count > 0) {
                out.printf("    %-10s : %d%n", sev, count);
            }
        }

        // Par type
        Map<String, Long> byType = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getType, Collectors.counting()));

        out.println("\n  Alertes par type :");
        byType.forEach((type, count) -> out.printf("    %-15s : %d%n", type, count));

        // IPs les plus dangereuses
        Map<String, Long> ipAlertCount = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getIpAddress, Collectors.counting()));

        List<Map.Entry<String, Long>> topIPs = ipAlertCount.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .toList();

        out.println("\n  Top 10 IPs les plus dangereuses :");
        int rank = 1;
        for (Map.Entry<String, Long> entry : topIPs) {
            out.printf("    %2d. %-18s : %d alerte(s)%n", rank++, entry.getKey(), entry.getValue());
        }
    }

    /**
     * 2. Timeline des incidents : alertes classees chronologiquement.
     */
    private void writeTimeline(PrintWriter out, List<Alert> alerts) {
        out.println("\n" + "-".repeat(80));
        out.println("2. TIMELINE DES INCIDENTS");
        out.println("-".repeat(80));

        List<Alert> sorted = alerts.stream()
                .sorted(Comparator.comparing(Alert::getTimestamp))
                .toList();

        for (Alert alert : sorted) {
            out.printf("  [%s] %-10s %-15s %-18s %s%n",
                    alert.getTimestamp().format(FMT),
                    alert.getSeverity(),
                    alert.getType(),
                    alert.getIpAddress(),
                    truncate(alert.getDescription(), 60));
        }
    }

    /**
     * 3. Detail par IP suspecte : toutes les alertes associees.
     */
    private void writeDetailByIP(PrintWriter out, List<Alert> alerts) {
        out.println("\n" + "-".repeat(80));
        out.println("3. DETAIL PAR IP SUSPECTE");
        out.println("-".repeat(80));

        Map<String, List<Alert>> byIP = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getIpAddress));

        // Trier par nombre d'alertes decroissant
        List<Map.Entry<String, List<Alert>>> sortedIPs = byIP.entrySet().stream()
                .sorted((a, b) -> b.getValue().size() - a.getValue().size())
                .toList();

        for (Map.Entry<String, List<Alert>> entry : sortedIPs) {
            String ip = entry.getKey();
            List<Alert> ipAlerts = entry.getValue();

            long distinctDetectors = ipAlerts.stream().map(Alert::getType).distinct().count();
            Severity maxSeverity = ipAlerts.stream()
                    .map(Alert::getSeverity)
                    .max(Comparator.naturalOrder())
                    .orElse(Severity.LOW);

            out.printf("%n  === IP : %-18s | Alertes: %d | Detecteurs: %d | Severite max: %s ===%n",
                    ip, ipAlerts.size(), distinctDetectors, maxSeverity);

            for (Alert alert : ipAlerts) {
                out.printf("    [%s] %-10s %-15s %s%n",
                        alert.getTimestamp().format(FMT),
                        alert.getSeverity(),
                        alert.getType(),
                        truncate(alert.getDescription(), 60));
            }
        }
    }

    /**
     * 4. Regles de blocage iptables et .htaccess pour les IPs HIGH/CRITICAL.
     */
    private void writeBlockingRules(PrintWriter out, List<Alert> alerts) {
        out.println("\n" + "-".repeat(80));
        out.println("4. REGLES DE BLOCAGE");
        out.println("-".repeat(80));

        Set<String> dangerousIPs = alerts.stream()
                .filter(a -> a.getSeverity() == Severity.HIGH || a.getSeverity() == Severity.CRITICAL)
                .map(Alert::getIpAddress)
                .filter(ip -> !ip.equals("MULTIPLE"))
                .collect(Collectors.toCollection(TreeSet::new));

        if (dangerousIPs.isEmpty()) {
            out.println("\n  Aucune IP a bloquer.");
            return;
        }

        // Regles iptables
        out.println("\n  --- Regles iptables ---");
        for (String ip : dangerousIPs) {
            out.printf("  iptables -A INPUT -s %s -j DROP%n", ip);
        }

        // Regles .htaccess
        out.println("\n  --- Regles .htaccess ---");
        out.println("  <RequireAll>");
        out.println("    Require all granted");
        for (String ip : dangerousIPs) {
            out.printf("    Require not ip %s%n", ip);
        }
        out.println("  </RequireAll>");

        out.printf("%n  Total : %d IPs a bloquer%n", dangerousIPs.size());
    }

    /**
     * 5. Recommandations : actions suggerees pour chaque type de menace.
     */
    private void writeRecommendations(PrintWriter out, List<Alert> alerts) {
        out.println("\n" + "-".repeat(80));
        out.println("5. RECOMMANDATIONS");
        out.println("-".repeat(80));

        Set<String> detectedTypes = alerts.stream().map(Alert::getType).collect(Collectors.toSet());

        if (detectedTypes.contains("BRUTE_FORCE")) {
            out.println("\n  [BRUTE_FORCE]");
            out.println("  - Mettre en place un rate-limiting sur les pages de login (ex: fail2ban)");
            out.println("  - Implementer un CAPTCHA apres 3 tentatives echouees");
            out.println("  - Activer l'authentification multi-facteur (MFA)");
            out.println("  - Bloquer les IPs apres 10 echecs consecutifs");
        }

        if (detectedTypes.contains("SQL_INJECTION")) {
            out.println("\n  [SQL_INJECTION]");
            out.println("  - Utiliser des requetes preparees (PreparedStatement) exclusivement");
            out.println("  - Implementer une validation stricte des entrees utilisateur");
            out.println("  - Deployer un Web Application Firewall (WAF)");
            out.println("  - Appliquer le principe du moindre privilege sur la base de donnees");
        }

        if (detectedTypes.contains("DDOS")) {
            out.println("\n  [DDOS]");
            out.println("  - Deployer un CDN/proxy inverse (Cloudflare, AWS Shield)");
            out.println("  - Configurer le rate-limiting au niveau du serveur web");
            out.println("  - Mettre en place un systeme de detection/mitigation DDoS");
            out.println("  - Configurer des seuils d'alerte sur le monitoring");
        }

        if (detectedTypes.contains("SCAN")) {
            out.println("\n  [SCAN]");
            out.println("  - Supprimer ou restreindre l'acces aux interfaces d'administration");
            out.println("  - Masquer les headers de version du serveur");
            out.println("  - Bloquer les user-agents connus (sqlmap, nikto, etc.)");
            out.println("  - Mettre en place un IDS/IPS (Snort, Suricata)");
        }

        out.println("\n  [GENERAL]");
        out.println("  - Centraliser les logs dans un SIEM (ELK, Splunk)");
        out.println("  - Automatiser les alertes en temps reel");
        out.println("  - Effectuer des audits de securite reguliers");
        out.println("  - Maintenir les logiciels a jour (patches de securite)");
    }

    private String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
