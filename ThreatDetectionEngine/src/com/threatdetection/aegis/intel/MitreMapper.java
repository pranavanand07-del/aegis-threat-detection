package com.threatdetection.aegis.intel;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.platform.RuleCatalog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Maps fired rules to MITRE ATT&CK techniques using this project's own rule catalog. Local and offline; the mapping is approximate. */
public final class MitreMapper {
    private static final Map<String, String> TECHNIQUE = new HashMap<>();

    static {
        for (RuleCatalog.Rule r : RuleCatalog.RULES) if (r.technique() != null && !r.technique().isBlank()) TECHNIQUE.put(r.id(), r.technique());
    }

    private MitreMapper() {}

    public static List<Enrichment> forRules(List<AegisEvent.Contribution> rules, String externalMitre) {
        Set<String> seen = new LinkedHashSet<>();
        List<Enrichment> out = new ArrayList<>();
        for (AegisEvent.Contribution c : rules) {
            String t = TECHNIQUE.get(c.rule);
            if (t != null && c.score > 0 && seen.add(t)) {
                out.add(new Enrichment("MITRE ATT&CK", Enrichment.OK, "MAPPED", -1, t + " (via rule " + c.rule + ")", System.currentTimeMillis(), false));
            }
        }
        if (externalMitre != null && !externalMitre.isBlank() && seen.add(externalMitre)) {
            out.add(new Enrichment("MITRE ATT&CK", Enrichment.OK, "MAPPED", -1, externalMitre + " (reported by Wazuh)", System.currentTimeMillis(), false));
        }
        return out;
    }
}
