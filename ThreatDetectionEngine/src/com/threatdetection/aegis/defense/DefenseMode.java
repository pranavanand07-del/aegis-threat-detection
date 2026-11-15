package com.threatdetection.aegis.defense;

/** OFF: do nothing. DRY_RUN (default): decide and audit, but change nothing on the machine. ENFORCE: act for real. */
public enum DefenseMode { OFF, DRY_RUN, ENFORCE }
