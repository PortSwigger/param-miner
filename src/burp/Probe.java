package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Created by james on 24/11/2016.
 */
class Probe {
    public static byte APPEND = 0;
    public static byte PREPEND = 1;
    public static byte REPLACE = 2;

    private String base = "'";
    private String name;

    private String tip = "";
    private int severity;
    private ArrayList<String> breakStrings = new ArrayList<>();
    private ArrayList<String[]> escapeStrings = new ArrayList<>();
    private byte prefix = APPEND;
    private boolean randomAnchor = true;
    private boolean useCacheBuster = false;
    private int nextBreak = -1;
    private int nextEscape = -1;

    public boolean getRequireConsistentEvidence() {
        return requireConsistentEvidence;
    }

    public void setRequireConsistentEvidence(boolean requireConsistentEvidence) {
        this.requireConsistentEvidence = requireConsistentEvidence;
    }

    private boolean requireConsistentEvidence = false;


    public boolean useCacheBuster() {
        return useCacheBuster;
    }



    public Probe(String name, int severity, String... breakStrings) {
        this.name = name;
        this.severity = severity;
        this.breakStrings = new ArrayList<>(Arrays.asList(breakStrings));
    }

    public String getTip() {
        return tip;
    }

    public void setTip(String tip) {
        this.tip = tip;
    }

    public byte getPrefix() {
        return prefix;
    }

    public void setPrefix(byte prefix) {
        this.prefix = prefix;
    }

    public boolean getRandomAnchor() {
        return randomAnchor;
    }

    public void setRandomAnchor(boolean randomAnchor) {
        this.randomAnchor = randomAnchor;
        useCacheBuster = !randomAnchor;
    }

    public void setUseCacheBuster(boolean useCacheBuster) {
        this.useCacheBuster = useCacheBuster;
    }


    public String getBase() {
        return base;
    }

    public void setBase(String base) {
        this.base = base;
    }

    public void setEscapeStrings(String... args) {
        for (String arg : args) {
            escapeStrings.add(new String[]{arg});
        }
    }

    // args is a list of alternatives
    public void addEscapePair(String... args) {
        escapeStrings.add(args);
    }

    public String getNextBreak() {
        nextBreak++;
        return breakStrings.get(nextBreak % breakStrings.size());
    }

    public String[] getNextEscapeSet() {
        nextEscape++;
        return escapeStrings.get(nextEscape % escapeStrings.size());
    }

    public String getName() {
        return name;
    }

    public int getSeverity() {
        return severity;
    }

    static class ProbeResults {
        public HashSet<String> interesting = new HashSet<>();
        public HashSet<String> boring = new HashSet<>();
    }
}
