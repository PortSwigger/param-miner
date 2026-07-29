package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import static burp.Scan.request;

public class ProxyProbe {

    private final HttpHeader header;
    private String comment;

    private final InjectionType injectionType;
    private HttpRequest baseReq;
    private int sizeLimit = 0;
    private int sizeAdjustment = 0;

    public ProxyProbe(HttpHeader header, InjectionType injectionType) {
        this(header, injectionType, "");
    }

    public ProxyProbe(HttpHeader header, InjectionType injectionType, String comment) {
        this.header = header;
        this.injectionType = injectionType;
        this.comment = comment;
    }

    public ProxyProbe(HttpHeader header, ProxyProbe baseProbe) {
        this.header = header;
        this.injectionType = baseProbe.injectionType;
        importSettings(baseProbe);
    }

    void importSettings(ProxyProbe probe) {
        if (this.injectionType != probe.injectionType) throw new RuntimeException();
        this.setBaseReq(probe.baseReq);
        this.setSizeLimit(probe.sizeLimit);
        this.setSizeAdjustment(probe.sizeAdjustment);
    }

    public InjectionType getInjectionType() {
        return injectionType;
    }

    public String getComment() {
        return comment;
    }

    // offset 0 to cause error on back-end. -1 for accept
    public MontoyaRequestResponse probe(int offset) {
        assert baseReq != null;

        Utilities.sleep(Utilities.globalSettings.getInt("per-thread throttle"));

        int pad = getPad();
        if (pad+offset < 1) {
            offset = -pad+1;
        }

        HttpRequest attack = baseReq;
        String headerValue;

        switch (injectionType) {
            case VALUE_APPEND:
                headerValue = Utilities.randomString(pad+offset) + header.value();
                attack = attack.withHeader(header.name(), headerValue);
                break;
            case VALUE_PREPEND:
                headerValue = header.value() + Utilities.randomString(pad+offset);
                attack = attack.withHeader(header.name(), headerValue);
                break;
            case NAME_APPEND:
                attack = attack.withHeader(Utilities.randomString(pad+offset)+header.name(), header.value());
                break;
            case NAME_PREPEND:
                attack = attack.withHeader(header.name() + Utilities.randomString(pad+offset),  header.value());
                break;
            default:
                throw new RuntimeException("Unknown injection type");
        }

        attack = attack.withParameter(HttpParameter.urlParameter("cb", Utilities.randomString(8)));
        return request(attack, true);
    }

    public HttpHeader getHeader() {
        return header;
    }

    public int getPad() {
        int pad = sizeLimit - header.value().length();
        if (sizeAdjustment != 0) {
            pad = pad + sizeAdjustment - header.name().length();
        }

        return pad;
    }

    public void setSizeAdjustment(int sizeAdjustment) {
        this.sizeAdjustment = sizeAdjustment;
    }

    public int getSizeLimit() {
        return sizeLimit;
    }
    public void setBaseReq(HttpRequest baseReq) {
        this.baseReq = baseReq;
    }

    public void setSizeLimit(int sizeLimit) {
        this.sizeLimit = sizeLimit;
    }

}

enum InjectionType {
    VALUE_APPEND,
    VALUE_PREPEND,
    NAME_APPEND,
    NAME_PREPEND
}
