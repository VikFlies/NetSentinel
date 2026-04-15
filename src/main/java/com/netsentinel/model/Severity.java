package com.netsentinel.model;

/**
 * Niveaux de severite des alertes de securite.
 */
public enum Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /**
     * Augmente la severite d'un niveau.
     */
    public Severity escalate() {
        return switch (this) {
            case LOW -> MEDIUM;
            case MEDIUM -> HIGH;
            case HIGH -> CRITICAL;
            case CRITICAL -> CRITICAL;
        };
    }
}
