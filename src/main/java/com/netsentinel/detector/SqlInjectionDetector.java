package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Detecteur d'injections SQL dans les URLs des requetes.
 *
 * Recherche de patterns suspects : UNION SELECT, OR 1=1, comment sequences,
 * xp_cmdshell, information_schema, etc.
 * Case-insensitive.
 */
public class SqlInjectionDetector implements ThreatDetector {

    // Patterns SQL Injection (case-insensitive)
    private static final List<Pattern> SQL_PATTERNS = List.of(
            Pattern.compile("(?i)union\\s+(all\\s+)?select"),
            Pattern.compile("(?i)'\\s*(or|and)\\s+['\"]?\\d+\\s*=\\s*\\d"),
            Pattern.compile("(?i)'\\s+or\\s+'"),
            Pattern.compile("(?i)select\\s+.+\\s+from\\s"),
            Pattern.compile("(?i)insert\\s+into"),
            Pattern.compile("(?i)delete\\s+from"),
            Pattern.compile("(?i)drop\\s+(table|database)"),
            Pattern.compile("(?i)xp_cmdshell"),
            Pattern.compile("(?i)information_schema"),
            Pattern.compile("(?i)concat\\s*\\("),
            Pattern.compile("(?i)convert\\s*\\(\\s*int"),
            Pattern.compile("(?i)group\\s+by\\s+x"),
            Pattern.compile("(?i)sleep\\s*\\("),
            Pattern.compile("(?i)benchmark\\s*\\("),
            Pattern.compile("(?i)admin'\\s*--"),
            Pattern.compile("(?i)'\\s*--\\s*$"),
            Pattern.compile("(?i)1=1"),
            Pattern.compile("(?i)exec\\s"),
            Pattern.compile("(?i)0x3a")
    );

    @Override
    public String getName() {
        return "SQL_INJECTION";
    }

    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();

        for (LogEntry entry : entries) {
            String url = entry.getUrl();
            List<String> matchedPatterns = new ArrayList<>();

            for (Pattern p : SQL_PATTERNS) {
                if (p.matcher(url).find()) {
                    matchedPatterns.add(p.pattern());
                }
            }

            if (!matchedPatterns.isEmpty()) {
                // Severite basee sur le nombre de patterns matches
                Severity sev = matchedPatterns.size() >= 3 ? Severity.HIGH : Severity.MEDIUM;

                String desc = String.format(
                        "Injection SQL detectee dans l'URL : %s (%d pattern(s) match)",
                        truncate(url, 80), matchedPatterns.size()
                );

                alerts.add(new Alert(
                        getName(), sev, entry.getIpAddress(), desc,
                        entry.getTimestamp(), List.of(entry)
                ));
            }
        }

        return alerts;
    }

    private String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
