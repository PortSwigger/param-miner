package burp;

import burp.api.montoya.http.message.HttpHeader;

public class ProxyTransformationResult {

    final static byte UNINITIALIZED = 0;
    final static byte INCONSISTENT = 1;
    final static byte NO_CHANGE = 2;
    final static byte BLOCKED = 3;
    final static byte OVERWRITE = 4; // never actually used
    final static byte EXPAND = 5;
    final static byte SHRINK = 6;
    final static byte TERMINATED = 7;


    private byte result = UNINITIALIZED;

    MontoyaRequestResponse justUnder = null;
    MontoyaRequestResponse justOver = null;
    MontoyaRequestResponse wayUnder = null;
    MontoyaRequestResponse wayOver = null;

    boolean valueIsRelevant = false;
    String comment = "";

    int transformation = 0;
    HttpHeader header;


    public ProxyTransformationResult(ProxyProbe probe) {
        this.header = probe.getHeader();
        this.comment = probe.getComment();
    }

    public boolean consistentCode() {
        return (justOver == null || justUnder == null);
    }

    public byte getResult() {
        return result;
    }

    public void setResult(byte result) {
        if (result != TERMINATED && this.result != 0 && result != this.result && result != BLOCKED) {
            this.result = INCONSISTENT;
            return;
        }
        this.result = result;
    }

    public HttpHeader getHeader() {
        return header;
    }

    public String getComment() {
        return comment;
    }

    public boolean isInteresting() {
        return result >= ProxyTransformationResult.OVERWRITE;
    }

    public String generateDescription() {
        StringBuilder detail = new StringBuilder();

        if (justUnder != null) {
            detail.append(justUnder.status());
        } else {
            detail.append("*");
        }
        detail.append("/");
        if (justOver != null) {
            detail.append(justOver.status());
        } else {
            detail.append("*");
        }

        detail.append(" ");
        detail.append(transformation);
        detail.append(" ");
        String message;
        switch (getResult()) {
            case ProxyTransformationResult.SHRINK:
                message = "shrink";
                break;
            case ProxyTransformationResult.EXPAND:
                message = "expand";
                break;
            case ProxyTransformationResult.OVERWRITE:
                message = "overwrite";
                break;
            case ProxyTransformationResult.BLOCKED:
                message = "blocked";
                break;
            case ProxyTransformationResult.INCONSISTENT:
                message = "inconsistent";
                break;
            case ProxyTransformationResult.NO_CHANGE:
                message = "nada";
                break;
            case ProxyTransformationResult.TERMINATED:
                message = "terminated";
                break;
            default:
                message = "unknown";
        }
        detail.append(message);
        detail.append(" ");
        detail.append(getComment());


        detail.append(">> ");
        detail.append(getHeader().toString());
        return detail.toString();
    }

}
