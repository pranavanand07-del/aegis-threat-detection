package com.threatdetection.model;

public class DetectionOutcome {
    public final String ruleName;
    public final int score;
    public final String detail;

    public DetectionOutcome(String ruleName, int score, String detail) {
        this.ruleName = ruleName;
        this.score = score;
        this.detail = detail;
    }
}
