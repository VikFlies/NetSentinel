package com.netsentinel.whitelist;

import com.netsentinel.model.Alert;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Gestionnaire de liste blanche.
 * Les IPs whitelistees ne declenchent jamais d'alertes.
 * Lit le fichier whitelist.txt (une IP par ligne, lignes commencant par # ignorees).
 */
public class WhitelistManager {

    private final Set<String> whitelistedIPs = new HashSet<>();

    /**
     * Charge la whitelist depuis un fichier.
     * @param filePath chemin vers whitelist.txt
     */
    public void loadWhitelist(String filePath) {
        whitelistedIPs.clear();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Ignorer les commentaires et les lignes vides
                if (!line.isEmpty() && !line.startsWith("#")) {
                    whitelistedIPs.add(line);
                }
            }
            System.out.println("  Whitelist chargee : " + whitelistedIPs.size() + " IPs");
        } catch (IOException e) {
            System.out.println("  Whitelist non trouvee (" + filePath + "), aucune IP whitelistee.");
        }
    }

    /**
     * Verifie si une IP est whitelistee.
     */
    public boolean isWhitelisted(String ip) {
        return whitelistedIPs.contains(ip);
    }

    /**
     * Filtre les alertes : supprime celles dont l'IP est whitelistee.
     * @param alerts liste d'alertes a filtrer
     * @return liste filtree
     */
    public List<Alert> filterAlerts(List<Alert> alerts) {
        int before = alerts.size();
        List<Alert> filtered = alerts.stream()
                .filter(a -> !isWhitelisted(a.getIpAddress()))
                .toList();
        int removed = before - filtered.size();
        if (removed > 0) {
            System.out.println("  Whitelist : " + removed + " alerte(s) supprimee(s) (IPs whitelistees)");
        }
        return new java.util.ArrayList<>(filtered);
    }

    public Set<String> getWhitelistedIPs() {
        return whitelistedIPs;
    }
}
