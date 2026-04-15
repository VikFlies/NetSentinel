package com.netsentinel;

import com.netsentinel.analyzer.DashboardAnalyzer;
import com.netsentinel.detector.*;
import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.parser.LogParser;
import com.netsentinel.report.ReportGenerator;
import com.netsentinel.whitelist.WhitelistManager;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Point d'entree de l'application NetSentinel.
 * Menu console interactif pour :
 * - Charger et parser des logs
 * - Afficher le dashboard statistique
 * - Lancer la detection de menaces
 * - Generer le rapport de securite
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);
    private static final LogParser parser = new LogParser();
    private static final WhitelistManager whitelist = new WhitelistManager();
    private static List<Alert> currentAlerts = new ArrayList<>();
    private static boolean logsLoaded = false;

    public static void main(String[] args) {
        printBanner();

        // Charger la whitelist
        whitelist.loadWhitelist("whitelist.txt");

        boolean running = true;
        while (running) {
            printMenu();
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1" -> loadLogFile();
                case "2" -> showDashboard();
                case "3" -> runDetection();
                case "4" -> showAlerts();
                case "5" -> generateReport();
                case "6" -> analyzeAttackFile();
                case "7" -> fullAnalysis();
                case "0" -> {
                    System.out.println("\n  Au revoir !");
                    running = false;
                }
                default -> System.out.println("\n  Choix invalide. Reessayez.");
            }
        }
    }

    private static void printBanner() {
        System.out.println("""

                ================================================================
                     _   _      _   ____             _   _            _
                    | \\ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
                    |  \\| |/ _ \\ __\\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |
                    | |\\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |
                    |_| \\_|\\___|\\__|____/ \\___|_| |_|\\__|_|_| |_|\\___|_|

                    Analyseur de logs reseau & Detecteur d'intrusion
                    Projet Cybersecurite - Java 17+
                ================================================================
                """);
    }

    private static void printMenu() {
        System.out.println("""

                ==================== MENU PRINCIPAL ====================
                  1. Charger un fichier de logs
                  2. Afficher le dashboard statistique
                  3. Lancer la detection de menaces
                  4. Afficher les alertes detectees
                  5. Generer le rapport de securite
                  6. Analyser le fichier d'attaque (access_log_attack.txt)
                  7. Analyse complete (clean + attack + rapport)
                  0. Quitter
                =========================================================
                """);
        System.out.print("  Votre choix > ");
    }

    // ====== 1. Charger un fichier de logs ======

    private static void loadLogFile() {
        System.out.print("\n  Chemin du fichier de logs (ou 'clean'/'attack') > ");
        String input = scanner.nextLine().trim();

        String filePath = switch (input.toLowerCase()) {
            case "clean" -> "data/access_log_clean.txt";
            case "attack" -> "data/access_log_attack.txt";
            default -> input;
        };

        try {
            System.out.println("\n  Parsing du fichier : " + filePath);
            int count = parser.parseFile(filePath);
            System.out.println("  Lignes parsees avec succes : " + count);
            System.out.println("  Erreurs de parsing        : " + parser.getParseErrors());
            logsLoaded = true;
            currentAlerts.clear();
        } catch (IOException e) {
            System.out.println("  ERREUR : impossible de lire le fichier -> " + e.getMessage());
        }
    }

    // ====== 2. Dashboard ======

    private static void showDashboard() {
        if (!checkLogsLoaded()) return;
        DashboardAnalyzer dashboard = new DashboardAnalyzer(parser.getEntries());
        dashboard.printDashboard();
    }

    // ====== 3. Detection de menaces ======

    private static void runDetection() {
        if (!checkLogsLoaded()) return;

        System.out.println("\n  Lancement de la detection de menaces...\n");

        List<ThreatDetector> detectors = List.of(
                new BruteForceDetector(),
                new SqlInjectionDetector(),
                new DDoSDetector(),
                new ScanDetector()
        );

        currentAlerts = new ArrayList<>();

        for (ThreatDetector detector : detectors) {
            List<Alert> alerts = detector.detect(parser.getEntries());
            System.out.printf("  [%s] %d alerte(s) detectee(s)%n", detector.getName(), alerts.size());
            currentAlerts.addAll(alerts);
        }

        // Filtrer par whitelist
        currentAlerts = whitelist.filterAlerts(currentAlerts);

        // Correlation
        System.out.println("\n  Correlation des alertes...");
        AlertCorrelator correlator = new AlertCorrelator();
        currentAlerts = correlator.correlate(currentAlerts);

        // Resume
        Map<Severity, Long> distribution = correlator.getSeverityDistribution(currentAlerts);
        System.out.println("\n  === RESUME DE LA DETECTION ===");
        System.out.println("  Total alertes : " + currentAlerts.size());
        for (Severity sev : Severity.values()) {
            long count = distribution.getOrDefault(sev, 0L);
            if (count > 0) {
                System.out.printf("    %-10s : %d%n", sev, count);
            }
        }

        Set<String> dangerousIPs = correlator.getDangerousIPs(currentAlerts);
        System.out.println("  IPs dangereuses (HIGH/CRITICAL) : " + dangerousIPs.size());
    }

    // ====== 4. Afficher les alertes ======

    private static void showAlerts() {
        if (currentAlerts.isEmpty()) {
            System.out.println("\n  Aucune alerte. Lancez d'abord la detection (option 3).");
            return;
        }

        System.out.println("\n  === ALERTES DETECTEES (" + currentAlerts.size() + ") ===\n");

        // Trier par severite (CRITICAL d'abord) puis par timestamp
        List<Alert> sorted = currentAlerts.stream()
                .sorted(Comparator.comparing(Alert::getSeverity).reversed()
                        .thenComparing(Alert::getTimestamp))
                .toList();

        for (Alert alert : sorted) {
            System.out.println("  " + alert);
        }

        // Resume par IP
        System.out.println("\n  === RESUME PAR IP ===");
        Map<String, Long> byIP = currentAlerts.stream()
                .collect(Collectors.groupingBy(Alert::getIpAddress, Collectors.counting()));

        byIP.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(15)
                .forEach(e -> System.out.printf("    %-18s : %d alerte(s)%n", e.getKey(), e.getValue()));
    }

    // ====== 5. Generer le rapport ======

    private static void generateReport() {
        if (currentAlerts.isEmpty()) {
            System.out.println("\n  Aucune alerte. Lancez d'abord la detection (option 3).");
            return;
        }

        try {
            String outputPath = "rapport_securite.txt";
            ReportGenerator generator = new ReportGenerator();
            generator.generateReport(currentAlerts, outputPath);
            System.out.println("\n  Rapport genere avec succes : " + outputPath);
        } catch (IOException e) {
            System.out.println("  ERREUR : " + e.getMessage());
        }
    }

    // ====== 6. Analyser le fichier d'attaque ======

    private static void analyzeAttackFile() {
        try {
            String filePath = "data/access_log_attack.txt";
            System.out.println("\n  Chargement de " + filePath + "...");
            int count = parser.parseFile(filePath);
            System.out.println("  Lignes parsees : " + count);
            logsLoaded = true;

            // Lancer la detection
            runDetection();

        } catch (IOException e) {
            System.out.println("  ERREUR : " + e.getMessage());
        }
    }

    // ====== 7. Analyse complete ======

    private static void fullAnalysis() {
        System.out.println("\n  ====== ANALYSE COMPLETE ======\n");

        try {
            // 1. Analyser le fichier clean
            System.out.println("  --- Analyse du fichier CLEAN ---");
            parser.parseFile("data/access_log_clean.txt");
            System.out.println("  Lignes parsees : " + parser.getTotalParsed());

            DashboardAnalyzer dashClean = new DashboardAnalyzer(parser.getEntries());
            dashClean.printDashboard();

            // 2. Analyser le fichier attack
            System.out.println("\n  --- Analyse du fichier ATTACK ---");
            parser.parseFile("data/access_log_attack.txt");
            System.out.println("  Lignes parsees : " + parser.getTotalParsed());
            logsLoaded = true;

            DashboardAnalyzer dashAttack = new DashboardAnalyzer(parser.getEntries());
            dashAttack.printDashboard();

            // 3. Detection
            runDetection();

            // 4. Afficher les alertes
            showAlerts();

            // 5. Generer le rapport
            generateReport();

            System.out.println("\n  ====== ANALYSE COMPLETE TERMINEE ======");

        } catch (IOException e) {
            System.out.println("  ERREUR : " + e.getMessage());
        }
    }

    // ====== Utilitaires ======

    private static boolean checkLogsLoaded() {
        if (!logsLoaded) {
            System.out.println("\n  Aucun fichier de log charge. Utilisez l'option 1 ou 6 d'abord.");
            return false;
        }
        return true;
    }
}
