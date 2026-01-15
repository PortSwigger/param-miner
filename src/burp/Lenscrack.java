package burp;

import com.google.common.net.InternetDomainName;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;


public class Lenscrack extends Scan {

    static ConcurrentHashMap<String, Boolean> alreadyReported = new ConcurrentHashMap<>();

    Lenscrack(String name) {
        super(name);
        scanSettings.register("overlong-detection", true, "Use overlong dns labels for detection");
        scanSettings.register("auto-scan for proxyable destinations", true, "If wildcard-routing is detected, try to enumerate accessible domains. To configure related settings, run 'Identify proxyable destinations'");
        scanSettings.register("mining: filter 500s", true, "Don't report hostnames that return a 50X status");
        scanSettings.register("subdomains-builtin", true, "Use the builtin wordlist to discover interesting proxyable destinations");
        scanSettings.register("subdomains-generic", "", "/path/to/wordlist");
        scanSettings.register("subdomains-specific", "", "Format: /subdomains/$domain. Read https://github.com/PortSwigger/param-miner/proxy.md for further info.");
        scanSettings.register("external subdomain lookup", false, "Look up subdomains using ip.thc.org/api/v1/lookup/subdomains. Warning: this discloses the top-level private domain that you are targeting.");
        scanSettings.register("I read the docs", false, "Read the docs at https://github.com/PortSwigger/param-miner/proxy.md then check this box to stop nagging me to read the docs.");
        scanSettings.register("deep-scan", false, "Prevent early exit if nothing interesting is found within the first 100 attempts or so. Always check all entries in enabled wordlists.");
    }

    static String TARGETHEADER = "Host";

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        String endpointHostname = service.getHost();

        String filteredDomain = endpointHostname.replaceAll("[^a-zA-Z0-9._-]", "");
        if (!endpointHostname.equals(filteredDomain)) {
            Utilities.out("Invalid domain: " + filteredDomain);
            return null;
        }

        if (endpointHostname.endsWith(".mil")) {
            return null;
        }

        String topPrivateDomain = InternetDomainName.from(endpointHostname).topPrivateDomain().toString();
        if (alreadyReported.containsKey(topPrivateDomain)) {
            // optimisation, could miss some stuff
            return null;
        }

        // skip already-detected targets
//        String domainFilePath = "/Users/james.kettle/data/domains/"+host;
//        File domainFile = new File(domainFilePath);
//        if (domainFile.exists()) {
//            return null;
//        }

        //baseReq = Utilities.setBody(baseReq, "x=1");
        //baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Length", "3");
        //baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Type", "application/x-www-form-urlencoded");

        //baseReq = Utilities.setPath(baseReq, "/");
        baseReq = Utilities.setMethod(baseReq, "GET");
        baseReq = Utilities.convertToHttp1(baseReq);

        baseReq = Utilities.addOrReplaceHeader(baseReq, "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Safari/537.36");
        //byte[] withCacheBuster = Utilities.appendToQuery(baseReq, "cb=zxcv");


        Lensprobe subDomain = new Lensprobe(baseReq, service, INJECT+"."+topPrivateDomain, "subdomain"); // $inject.example.com
        if (!subDomain.failed()) {
            //LensAltTPD.scan(baseReq, service); // only trying this if they have a subdomain wildcard is good for efficiency

            Lensprobe endsWith = new Lensprobe(baseReq, service, INJECT + topPrivateDomain, "endswith"); // $injectexample.com
//            if (!endsWith.failed()) {
//                new Lensprobe(baseReq, service, topPrivateDomain + INJECT, "contains"); // example.com$inject
//            }
        }
//        if (endsWith.failed()) {
//            new Lensprobe(baseReq, service, INJECT + endpointHostname, "endswith-subdomain"); // $injectapi.example.com
//        }
        //}
//        trySuffix(baseReq, service, endpointHostname+INJECT, "startswith"); // api.example.com$inject
//
//        trySuffix




        return null;
    }

    static final String INJECT = "$inject";


    static String buildComparisonTable(RespPair... pairs) {
        StringBuilder detail = new StringBuilder();

        for (RespPair pair: pairs) {
            detail.append("Iterations: ");
            detail.append(pair.iterations);
            detail.append("<br/> Closest: ");
            detail.append(pair.closestTimingDiff);
            detail.append("<br/>");
            detail.append("Timing: ");
            detail.append(pair.timingData);
            detail.append("<br/>--------<br/>");
        }

        detail.append("<table>");
        detail.append("<tr><td>Host</td><td>Status</td><td>Length</td><td>Time</td></tr>");
        for (RespPair pair: pairs) {
            detail.append("<tr><td>");
            detail.append(pair.slowResp.request().headerValue(TARGETHEADER));
            detail.append("</td><td>");
            detail.append(pair.slowResp.response().statusCode());
            detail.append("</td><td>");
            detail.append(pair.slowResp.response().toString().length());
            detail.append("</td><td>");
            detail.append(pair.slowTime.toMillis());
            detail.append("</td></tr>");

            detail.append("<tr><td>");
            detail.append(pair.fastResp.request().headerValue(TARGETHEADER));
            detail.append("</td><td>");
            detail.append(pair.fastResp.response().statusCode());
            detail.append("</td><td>");
            detail.append(pair.fastResp.response().toString().length());
            detail.append("</td><td>");
            detail.append(pair.fastTime.toMillis());
            detail.append("</td></tr>");

            detail.append("<tr><td></td><td></td><td></td></tr>");
        }

        detail.append("</table>");
        return detail.toString();
    }

    static void reportPairs(String title, String findings, String domain, byte[] baseReq, RespPair... pairs) {
        alreadyReported.put(domain, true);

        ArrayList<Resp> responses = new ArrayList<>();
        for (RespPair pair: pairs) {
            responses.add(new Resp(pair.slowResp));
            responses.add(new Resp(pair.fastResp));
        }

        String detail = buildComparisonTable(pairs);
        //detail.append("<pre>"+pairs[0].fastResp.response().headers().toString().replaceAll("\n", "<br/>")+"</pre>");

        report(title, detail+findings, baseReq, responses.toArray(new Resp[0]));
    }






//    void dotBypass(byte[] baseReq, String host, IHttpService service) {
//        service.getHost().replaceFirst("[.]", "x");
//        byte[] bypass = Utilities.addOrReplaceHeader(baseReq, "Host", "$canary"+host);
//        byte[] noBypass = Utilities.addOrReplaceHeader(baseReq, "Host", "$canaryxy"+host);
//        RespPair subCheck = new RespPair(bypass, noBypass, service, true, 4);
//        if (!(subCheck.timingDiff || subCheck.codeDiff)) {
//            return;
//        }
//        reportPairs("Dot bypass v0.1", "", host, baseReq, subCheck);
//        // todo report
//    }
//
//
//    static RespPair overlongDirect(byte[] baseReq, String host, IHttpService service) {
//
//        String invalidHost = Lensprobe.permute(host);
//        int MAX_DNS_LABEL_LENGTH = 63;
//        int suffixLength = host.split("[.]")[0].length();
//        String tooLongInvalid = "a".repeat((MAX_DNS_LABEL_LENGTH - suffixLength) + 1) + invalidHost;
//        String tooLongValid = "a".repeat((MAX_DNS_LABEL_LENGTH - suffixLength) + 1) + host;
//        byte[] right = Utilities.addOrReplaceHeader(baseReq, "Host", tooLongInvalid);
//        byte[] left = Utilities.addOrReplaceHeader(baseReq, "Host", tooLongValid);
//        RespPair overlong = new RespPair(left, right, service, true, 5, false, 100);
//        if (overlong.codeDiff || overlong.timingDiff) {
//            reportPairs("Endswith overlong direct v0.2", "", host, baseReq, overlong);
//        }
//
//        return null;
//    }
//
//    static RespPair endswithBypass(byte[] baseReq, String host, IHttpService service) {
//        byte[] bypass = Utilities.addOrReplaceHeader(baseReq, "Host", "$canary"+host);
//        byte[] noBypass = Utilities.addOrReplaceHeader(baseReq, "Host", host.replaceFirst("[.]", "\\$canary.")); //
//        RespPair subCheck = new RespPair(bypass, noBypass, service, true, 5, false, 100);
//        if (!subCheck.codeDiff && !subCheck.timingDiff) {
//            return null;
//        }
//
//        if (subCheck.codeDiff) {
//            reportPairs("Endswith status bypass v0.4", "", host, baseReq, subCheck);
//        } else if (subCheck.timingDiff) {
//            reportPairs("Endswith time bypass v0.4", "", host, baseReq, subCheck);
//        }
//
//        byte[] cached = Utilities.addOrReplaceHeader(baseReq, "Host", "staticxyz"+host);
//        byte[] uncached = Utilities.addOrReplaceHeader(baseReq, "Host", "$canary"+host);
//        Lensprobe.send(cached, service);
//        Lensprobe.send(cached, service);
//        RespPair cachedCheck = new RespPair(cached, uncached, service, true, 5, false, 100);
//        if (cachedCheck.codeDiff || cachedCheck.timingDiff) {
//            reportPairs("Endswith cached bypass! v0.1", "", host, baseReq, cachedCheck);
//        }
//
//        byte[] right = Utilities.addOrReplaceHeader(baseReq, "Host", Lensprobe.pad(host, false));
//        byte[] left = Utilities.addOrReplaceHeader(baseReq, "Host", Lensprobe.pad(host, true));
//        RespPair overlong = new RespPair(left, right, service, true, 5, false, 100);
//        if (overlong.codeDiff || overlong.timingDiff) {
//            reportPairs("Endswith overlong bypass! v0.1", "", host, baseReq, overlong);
//        }
//
//        return null;
//    }
}
