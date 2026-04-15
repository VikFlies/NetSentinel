package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;

import java.util.List;

/**
 * Interface commune pour tous les detecteurs de menaces.
 * Chaque detecteur analyse les logs et produit une liste d'alertes.
 */
public interface ThreatDetector {

    /**
     * Analyse la liste d'entrees de log et retourne les alertes detectees.
     * @param entries les entrees de log a analyser
     * @return liste d'alertes generees
     */
    List<Alert> detect(List<LogEntry> entries);

    /**
     * Retourne le nom du detecteur.
     */
    String getName();
}
