package burp.model.utilities.scan;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by james on 24/11/2016.
 */
public class Probe {
public static final byte APPEND  = 0;
public static final byte PREPEND = 1;
public static final byte REPLACE = 2;

private final String              name;
private final int                 severity;
private final ArrayList<String>   breakStrings;
private final ArrayList<String[]> escapeStrings             = new ArrayList<>();
private final boolean             requireConsistentEvidence = false;

private String  tip            = "";
private byte    prefix         = APPEND;
private boolean randomAnchor   = true;
private boolean useCacheBuster = false;
private int     nextBreak      = -1;
private int     nextEscape     = -1;


    public boolean getRequireConsistentEvidence() {
        return requireConsistentEvidence;
    }


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

    public void setBase(String base) {
    }

    public void setEscapeStrings(String... args) {
        for (String arg : args) {
            escapeStrings.add(new String[]{arg});
        }
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
  
}
