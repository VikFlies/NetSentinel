package com.netsentinel.model;

import java.time.LocalDateTime;

/**
 * Modele representant une entree de log Apache Combined Log Format.
 *
 * Format : IP - user [timestamp] "METHOD URL PROTOCOL" status size "referer" "user-agent"
 */
public class LogEntry {

    private final String ipAddress;
    private final String user;
    private final LocalDateTime timestamp;
    private final String method;
    private final String url;
    private final String protocol;
    private final int statusCode;
    private final long responseSize;
    private final String referer;
    private final String userAgent;
    private final String rawLine;

    public LogEntry(String ipAddress, String user, LocalDateTime timestamp,
                    String method, String url, String protocol,
                    int statusCode, long responseSize,
                    String referer, String userAgent, String rawLine) {
        this.ipAddress = ipAddress;
        this.user = user;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.protocol = protocol;
        this.statusCode = statusCode;
        this.responseSize = responseSize;
        this.referer = referer;
        this.userAgent = userAgent;
        this.rawLine = rawLine;
    }

    // --- Getters ---

    public String getIpAddress()    { return ipAddress; }
    public String getUser()         { return user; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getMethod()       { return method; }
    public String getUrl()          { return url; }
    public String getProtocol()     { return protocol; }
    public int getStatusCode()      { return statusCode; }
    public long getResponseSize()   { return responseSize; }
    public String getReferer()      { return referer; }
    public String getUserAgent()    { return userAgent; }
    public String getRawLine()      { return rawLine; }

    @Override
    public String toString() {
        return String.format("[%s] %s %s %s -> %d", timestamp, ipAddress, method, url, statusCode);
    }
}
