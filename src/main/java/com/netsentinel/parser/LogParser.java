package com.netsentinel.parser;

import com.netsentinel.model.LogEntry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parseur de fichiers de logs Apache Combined Log Format.
 * Utilise java.util.regex pour extraire les champs de chaque ligne.
 *
 * Indexation :
 *  - HashMap<String, List<LogEntry>> par IP
 *  - TreeMap<LocalDateTime, List<LogEntry>> par timestamp
 */
public class LogParser {

    // Regex pour le format Apache Combined Log
    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^(\\S+) \\S+ (\\S+) \\[([^\\]]+)] \"(\\S+) (.+?) (\\S+)\" (\\d{3}) (\\d+|-) \"([^\"]*)\" \"([^\"]*)\"$"
    );

    // Format du timestamp Apache : 15/Mar/2025:10:23:45 +0100
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private final List<LogEntry> entries = new ArrayList<>();
    private final HashMap<String, List<LogEntry>> indexByIP = new HashMap<>();
    private final TreeMap<LocalDateTime, List<LogEntry>> indexByTime = new TreeMap<>();
    private int parseErrors = 0;

    /**
     * Parse un fichier de log ligne par ligne.
     * @param filePath chemin vers le fichier de log
     * @return nombre de lignes parsees avec succes
     */
    public int parseFile(String filePath) throws IOException {
        entries.clear();
        indexByIP.clear();
        indexByTime.clear();
        parseErrors = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                LogEntry entry = parseLine(line);
                if (entry != null) {
                    entries.add(entry);

                    // Indexation par IP
                    indexByIP.computeIfAbsent(entry.getIpAddress(), k -> new ArrayList<>()).add(entry);

                    // Indexation par timestamp
                    indexByTime.computeIfAbsent(entry.getTimestamp(), k -> new ArrayList<>()).add(entry);
                } else {
                    parseErrors++;
                }
            }
        }
        return entries.size();
    }

    /**
     * Parse une seule ligne de log.
     * @return LogEntry ou null si la ligne ne correspond pas au format
     */
    public LogEntry parseLine(String line) {
        if (line == null || line.isBlank()) return null;

        Matcher m = LOG_PATTERN.matcher(line.trim());
        if (!m.matches()) return null;

        try {
            String ip = m.group(1);
            String user = m.group(2);
            String rawTimestamp = m.group(3);
            String method = m.group(4);
            String url = m.group(5);
            String protocol = m.group(6);
            int statusCode = Integer.parseInt(m.group(7));
            long responseSize = m.group(8).equals("-") ? 0 : Long.parseLong(m.group(8));
            String referer = m.group(9);
            String userAgent = m.group(10);

            // Parser le timestamp avec le fuseau horaire
            LocalDateTime timestamp = LocalDateTime.parse(rawTimestamp, DATE_FORMAT);

            return new LogEntry(ip, user, timestamp, method, url, protocol,
                    statusCode, responseSize, referer, userAgent, line);
        } catch (Exception e) {
            return null;
        }
    }

    // --- Accesseurs ---

    public List<LogEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public HashMap<String, List<LogEntry>> getIndexByIP() {
        return indexByIP;
    }

    public TreeMap<LocalDateTime, List<LogEntry>> getIndexByTime() {
        return indexByTime;
    }

    public int getParseErrors() {
        return parseErrors;
    }

    public int getTotalParsed() {
        return entries.size();
    }
}
