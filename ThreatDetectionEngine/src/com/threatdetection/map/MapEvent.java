package com.threatdetection.map;

import com.threatdetection.geo.GeoLocation;
import com.threatdetection.model.ThreatLevel;

/** One geolocated event in the live feed that drives the attack animations. */
public class MapEvent {
    public final long id;
    public final long timestamp;
    public final String ip;
    public final GeoLocation location;
    public final ThreatLevel level;
    public final int risk;
    public final String threat;        // dominant rule name, may be null
    public final boolean blocked;
    public final String targetKind;    // null for SAFE traffic
    public final String targetName;

    public MapEvent(long id, long timestamp, String ip, GeoLocation location, ThreatLevel level,
                    int risk, String threat, boolean blocked, String targetKind, String targetName) {
        this.id = id;
        this.timestamp = timestamp;
        this.ip = ip;
        this.location = location;
        this.level = level;
        this.risk = risk;
        this.threat = threat;
        this.blocked = blocked;
        this.targetKind = targetKind;
        this.targetName = targetName;
    }
}
