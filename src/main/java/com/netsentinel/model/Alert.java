package com.netsentinel.model;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Represente une alerte de securite generee par un detecteur.
 */
public class Alert {

    private final String type;           // "BRUTE_FORCE", "SQL_INJECTION", "DDOS", "SCAN"
    private Severity severity;
    private final String ipAddress;
    private final String description;
    private final LocalDateTime timestamp;
    private final List<LogEntry> relatedEntries;

    public Alert(String type, Severity severity, String ipAddress,
                 String description, LocalDateTime timestamp,
                 List<LogEntry> relatedEntries) {
        this.type = type;
        this.severity = severity;
        this.ipAddress = ipAddress;
        this.description = description;
        this.timestamp = timestamp;
        this.relatedEntries = relatedEntries;
    }

    // --- Getters ---

    public String getType()                  { return type; }
    public Severity getSeverity()            { return severity; }
    public String getIpAddress()             { return ipAddress; }
    public String getDescription()           { return description; }
    public LocalDateTime getTimestamp()       { return timestamp; }
    public List<LogEntry> getRelatedEntries() { return relatedEntries; }

    // --- Setter pour la correlation ---

    public void setSeverity(Severity severity) { this.severity = severity; }

    @Override
    public String toString() {
        return String.format("[%s] %-10s | %-8s | %-18s | %s",
                timestamp, severity, type, ipAddress, description);
    }
}
