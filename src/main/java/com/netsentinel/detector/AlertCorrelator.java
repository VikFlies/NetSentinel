package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.Severity;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Correlateur d'alertes multi-detecteur.
 *
 * Regles de correlation :
 * - 1 detecteur declenche  : severite inchangee
 * - 2 detecteurs declenches : severite +1 niveau (ex: MEDIUM -> HIGH)
 * - 3+ detecteurs declenches : automatiquement CRITICAL
 */
public class AlertCorrelator {

    /**
     * Correle les alertes de tous les detecteurs.
     * Augmente la severite si une meme IP declenche plusieurs detecteurs.
     *
     * @param allAlerts toutes les alertes combinees
     * @return les alertes avec severite ajustee
     */
    public List<Alert> correlate(List<Alert> allAlerts) {

        // Grouper les alertes par IP
        Map<String, List<Alert>> alertsByIP = allAlerts.stream()
                .collect(Collectors.groupingBy(Alert::getIpAddress));

        for (Map.Entry<String, List<Alert>> entry : alertsByIP.entrySet()) {
            List<Alert> ipAlerts = entry.getValue();

            // Compter le nombre de detecteurs differents qui ont declenche pour cette IP
            long distinctDetectors = ipAlerts.stream()
                    .map(Alert::getType)
                    .distinct()
                    .count();

            if (distinctDetectors >= 3) {
                // 3+ detecteurs : tout passe en CRITICAL
                for (Alert alert : ipAlerts) {
                    alert.setSeverity(Severity.CRITICAL);
                }
            } else if (distinctDetectors == 2) {
                // 2 detecteurs : severite +1
                for (Alert alert : ipAlerts) {
                    alert.setSeverity(alert.getSeverity().escalate());
                }
            }
            // 1 detecteur : inchange
        }

        return allAlerts;
    }

    /**
     * Resume de la correlation : nombre d'alertes par severite.
     */
    public Map<Severity, Long> getSeverityDistribution(List<Alert> alerts) {
        return alerts.stream()
                .collect(Collectors.groupingBy(Alert::getSeverity, Collectors.counting()));
    }

    /**
     * Retourne les IPs classees HIGH ou CRITICAL.
     */
    public Set<String> getDangerousIPs(List<Alert> alerts) {
        return alerts.stream()
                .filter(a -> a.getSeverity() == Severity.HIGH || a.getSeverity() == Severity.CRITICAL)
                .map(Alert::getIpAddress)
                .collect(Collectors.toSet());
    }
}
