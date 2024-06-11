package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashMap;

import static burp.Lenscrack.INJECT;

public class Lensprobe {

    byte[] baseReq;
    IHttpService service;
    String template;
    String name;

    // HashMap<String, RespPair> findings = new HashMap<>();
    RespPair detectBasic = null;
    RespPair detectOverlong = null;
    RespPair confirmCache = null;
    RespPair confirmOverlong = null;
    RespPair mined = null;

    MineFindings mineFindings = null;
    int mineAttempts = 0;

    public Lensprobe(byte[] baseReq, IHttpService service, String template, String name) {
        this.baseReq = baseReq;
        this.service = service;
        this.template = template;
        this.name = name;
        probe();
    }

    static String pad(String host, boolean overlong) {
        int MAX_DNS_LABEL_LENGTH = 63;
        int suffixLength = host.split("[.]")[0].length();
        String padded;
        if (overlong) {
            padded = "a".repeat((MAX_DNS_LABEL_LENGTH - suffixLength) + 1) + host;
        } else {
            padded = "a".repeat(MAX_DNS_LABEL_LENGTH -suffixLength) + host;
        }
        return padded;
    }

    static String permute(String host) {
        StringBuilder invalidHost = new StringBuilder(host);
        int targetIndex = 0;

        while (true) {
            if (invalidHost.length() > targetIndex+ Lenscrack.INJECT.length() && Lenscrack.INJECT.equals(invalidHost.substring(targetIndex, targetIndex+ Lenscrack.INJECT.length()))) {
                targetIndex += Lenscrack.INJECT.length();
                continue;
            }
            if (invalidHost.charAt(targetIndex) == '.') {
                targetIndex += 1;
                continue;
            }

            break;
        }

        invalidHost.setCharAt(targetIndex, 'z');
        if (invalidHost.toString().equals(host)) {
            invalidHost.setCharAt(targetIndex, 'y');
        }
        return invalidHost.toString();
    }

    void probe() {
        String title = "";
        int domainsToCheck = 100;

        // check for suffix validation
        byte[] randomWithSuffix = Utilities.addOrReplaceHeader(baseReq, Lenscrack.TARGETHEADER, template.replace(Lenscrack.INJECT, "$canary"));
        byte[] randomWithoutSuffix = Utilities.addOrReplaceHeader(baseReq, Lenscrack.TARGETHEADER, permute(template).replace(Lenscrack.INJECT, "$canary"));
        RespPair suffixCheck = new RespPair(randomWithSuffix, randomWithoutSuffix, service);

        boolean anyDetection = false;
        // check for suffix validation w/visible caching
        if (suffixCheck.timingDiff || suffixCheck.codeDiff) {
            detectBasic = suffixCheck;
            // Lenscrack.reportPairs("Basic detection "+name, "", template, baseReq, suffixCheck);

            // check for visible DNS caching
            byte[] staticSub = Utilities.addOrReplaceHeader(baseReq, Lenscrack.TARGETHEADER, template.replace(Lenscrack.INJECT, "ss"+Utilities.generateCanary()));
            // get the static subdomain cached
            for (int i=0;i<4;i++) {
                HttpRequestResponse stat = send(staticSub, service);
                if (!stat.hasResponse()) {
                    return;
                }
                Utilities.sleep(1000);
            }

            RespPair staticCheck = new RespPair(randomWithSuffix, staticSub, service);

            if (staticCheck.timingDiff) {
                anyDetection = true;
                confirmCache = staticCheck;
                // Lenscrack.reportPairs("Cached confirmation "+name, "", template, baseReq, staticCheck);
                domainsToCheck = 1000;
            }
        } else if (Utilities.globalSettings.getBoolean("overlong-detection")) {
            // todo refactor pad so it's not assuming a suffix
            byte[] overlongWithSuffix = Utilities.addOrReplaceHeader(baseReq, "Host", pad(template.replace(Lenscrack.INJECT, ""), true));
            byte[] overlongWithoutSuffix = Utilities.addOrReplaceHeader(baseReq, "Host", pad(permute(template).replace(Lenscrack.INJECT, ""), true));
            RespPair detectOverlong = new RespPair(overlongWithSuffix, overlongWithoutSuffix, service);
            if (detectOverlong.codeDiff || detectOverlong.timingDiff) {
                anyDetection = true;
                this.detectOverlong = detectOverlong;
                // Lenscrack.reportPairs("Overlong detection "+name, "", template, baseReq, detectOverlong);
            }
        }

        if (!anyDetection) {
            return;
        }

        byte[] overlongWithSuffix = Utilities.addOrReplaceHeader(baseReq, "Host", pad(template.replace(Lenscrack.INJECT, ""), true));
        byte[] notOverlongWithSuffix = Utilities.addOrReplaceHeader(baseReq, "Host", pad(template.replace(Lenscrack.INJECT, ""), false));
        RespPair overlong = new RespPair(overlongWithSuffix, notOverlongWithSuffix, service);
        if (overlong.codeDiff || overlong.timingDiff) {
            confirmOverlong = overlong;
            // Lenscrack.reportPairs("Overlong confirmation"+name, "", template, baseReq, overlong);
        }

        // alternative check for suffix validation, using an overlong label

        if (Utilities.globalSettings.getBoolean("auto-mine for subdomains")) {
            switch (name) {
                case "subdomain":
                    mineFindings = Lensmine.doScan(baseReq, service, domainsToCheck);
                    break;
                case "endswith":
                    mineForEndsWith();
                    break;
                default:
                    ;
            }
        }

        report();
    }

    void mineForEndsWith() {
        String domain = template.replace(Lenscrack.INJECT, "");
        DomainProvider domainProvider = new DomainProvider(domain, DomainProvider.ENDSWITH);
        String attackDomain;

        byte[] randomPrefix = Utilities.addOrReplaceHeader(baseReq, "Host", Utilities.generateCanary()+domain);
        int loops = 0;
        int shouldHaveWorked = 0;
        final int MAX_ATTEMPTS = 30;

        while ((attackDomain = domainProvider.getNextDomain()) != null && !Utilities.unloaded.get() && loops < MAX_ATTEMPTS && shouldHaveWorked < 10) {

            attackDomain = attackDomain + domain;
            loops += 1;
            byte[] attackReq = Utilities.addOrReplaceHeader(baseReq, "Host", attackDomain);

            try {
                HttpService directService = HttpService.httpService(attackDomain, service.getPort(), service.getPort() == 443);
                HttpRequest directRequest = HttpRequest.httpRequest(directService, ByteArray.byteArray(attackReq));
                HttpRequestResponse direct = Utilities.montoyaApi.http().sendRequest(directRequest);
                if (!direct.hasResponse()) {
                    continue;
                }
                //if (direct.response().statusCode() == )

            } catch (Exception e) {
                continue;
            }

            mineAttempts += 1;
            // fixme maybe don't ignore the time?
            RespPair subCheck = new RespPair(attackReq, randomPrefix, service, true);
            if (!subCheck.codeDiff) {
                shouldHaveWorked += 1;
                continue;
            }

            mined = subCheck;
        }
    }

    boolean failed() {
        return (detectBasic == null && detectOverlong == null);
    }

    void report() {
        if (failed()) {
            return;
        }

        StringBuilder title = new StringBuilder();
        title.append("Lenscrack ");
        title.append(name);
        title.append(" ");
        ArrayList<Resp> pairs = new ArrayList<>();
        StringBuilder detail = new StringBuilder();
        detail.append(template);
        detail.append("<br/>\n");
        if (detectBasic != null) {
            title.append("basic/");
            detail.append(Lenscrack.buildComparisonTable(detectBasic));
            pairs.add(new Resp(detectBasic.fastResp));
            pairs.add(new Resp(detectBasic.slowResp));
        }
        if (detectOverlong != null) {
            title.append("overlong/");
            detail.append(Lenscrack.buildComparisonTable(detectOverlong));
            pairs.add(new Resp(detectOverlong.fastResp));
            pairs.add(new Resp(detectOverlong.slowResp));
        }
        if (confirmCache != null) {
            title.append("confirm-cache/");
            detail.append(Lenscrack.buildComparisonTable(confirmCache));
            pairs.add(new Resp(confirmCache.fastResp));
            pairs.add(new Resp(confirmCache.slowResp));
        }
        if (confirmOverlong != null) {
            title.append("confirm-overlong/");
            detail.append(Lenscrack.buildComparisonTable(confirmOverlong));
            pairs.add(new Resp(confirmOverlong.fastResp));
            pairs.add(new Resp(confirmOverlong.slowResp));
        }
        if (mined != null) {
            title.append("mined ");
            detail.append(Lenscrack.buildComparisonTable(mined));
            pairs.add(new Resp(mined.fastResp));
            pairs.add(new Resp(mined.slowResp));
        }

        if ("endswith".equals(name)) {
            title.append(mineAttempts);
        }

        if (mineFindings != null) {
            title.append("mined "+mineFindings.getTitle());
            detail.append(mineFindings.findingsToString());
        }

        if (detail.isEmpty()) {
            return;
        }

        Lenscrack.report(title.toString(), detail.toString(), baseReq, pairs.toArray(new Resp[0]));
    }

    static HttpRequestResponse send(byte[] req, IHttpService service) {
        return Utilities.montoyaApi.http().sendRequest(Utilities.buildMontoyaReq(Utilities.replace(req, "$canary", Utilities.generateCanary()), service));
    }
}
