package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import com.google.common.net.InternetDomainName;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class Lensmine extends Scan {


    public Lensmine(String name) {
        super(name);
        scanSettings.register("mining: filter 500s", true, "Don't report hostnames that return a 50X status");
        scanSettings.register("subdomains-builtin", true, "Use the builtin wordlist to discover interesting proxyable destinations");
        scanSettings.register("subdomains-generic", "", "/path/to/wordlist");
        scanSettings.register("subdomains-specific", "", "Format: /subdomains/$domain. Read https://github.com/PortSwigger/param-miner/proxy.md for further info.");
        scanSettings.register("external subdomain lookup", false, "Look up subdomains using columbus.elmasy.com. Warning: this discloses the top-level private domain that you are targeting.");
        scanSettings.register("I read the docs", false, "Read the docs at https://github.com/PortSwigger/param-miner/proxy.md then check this box to stop nagging me to read the docs.");
        scanSettings.register("deep-scan", false, "Prevent early exit if nothing interesting is found within the first 100 attempts or so. Always check all entries in enabled wordlists.");
    }

    static MineFindings mineSubdomains(byte[] req, IHttpService service, String domain, int maxDomainsToCheck) {
        if (!Utilities.globalSettings.getBoolean("I read the docs")) {
            String message = "To get the most out of Param Miner's proxyable-destination detection, please read the documentation at https://github.com/PortSwigger/param-miner/proxy.md To disable this message, check \"I read the docs\".";
            Utilities.out(message);
            Utilities.montoyaApi.logging().raiseInfoEvent(message);
        }

        // todo handle dupes - inside provider or externally?
        WordProvider subdomainProvider = new WordProvider();
        subdomainProvider.addSourceFile(Utilities.globalSettings.getString("subdomains-specific").replace("$domain", domain));
        if (Utilities.globalSettings.getBoolean("external subdomain lookup")) {
            try {
                String url = "https://columbus.elmasy.com/api/lookup/" + domain;
                HttpRequestResponse apiResp = Utilities.montoyaApi.http().sendRequest(HttpRequest.httpRequestFromUrl(url).withHeader("Accept", "text/plain"), RequestOptions.requestOptions().withUpstreamTLSVerification());
                subdomainProvider.addSourceWords(apiResp.response().bodyToString());
            } catch (Exception e) {
                Utilities.out("External subdomain lookup failed: "+e.toString());
            }
        }

        subdomainProvider.addSourceFile(Utilities.globalSettings.getString("subdomains-generic"));
        if (Utilities.globalSettings.getBoolean("subdomains-builtin")) {
            subdomainProvider.addSourceFile("/fierce-subdomains");
        }
        //subdomainProvider.addSourceFile(Utilities.globalSettings.getString("subdomain-wordlist"));

        String subdomain;
        MineFindings findings = new MineFindings();

        // override randomSub with no-url-cachebuster version
        HttpRequestResponse randomSub =  Lensprobe.send(Utilities.addOrReplaceHeader(req, Lenscrack.TARGETHEADER, Utilities.generateCanary()+"."+domain), service);
        HttpRequestResponse nestedSub = Lensprobe.send(Utilities.addOrReplaceHeader(req, Lenscrack.TARGETHEADER, Utilities.generateCanary()+"."+Utilities.generateCanary()+"."+domain), service);
        int checked = 0;

        CustomResponseGroup randomSubGroup = new CustomResponseGroup(Lensmine::calculateFingerprint, randomSub);
        CustomResponseGroup nestedSubGroup = new CustomResponseGroup(Lensmine::calculateFingerprint, nestedSub);

        ArrayList<CustomResponseGroup> validSubGroups = new ArrayList<>();

        while ((subdomain = subdomainProvider.getNext()) != null && !Utilities.unloaded.get()) {
            checked += 1;
            // Don't exit early if deep-scan enabled
            if (checked > maxDomainsToCheck && !Utilities.globalSettings.getBoolean("deep-scan")) {
                //Utilities.out("Bailing early on "+domain);
                break;
            }

            String fullDomain = subdomain + "." + domain;
            if (fullDomain.equals(service.getHost()) || "_dmarc".equals(subdomain) || subdomain.contains("*")) {
                continue;
            }

            // todo skip if IP matches/overlaps

            byte[] attackReq = Utilities.addOrReplaceHeader(req, Lenscrack.TARGETHEADER, fullDomain);
            Utilities.sleep(Utilities.globalSettings.getInt("per-thread throttle"));
            HttpRequestResponse proxied = Lensprobe.send(attackReq, service);
            if (!proxied.hasResponse() || proxied.response().statusCode() == 0) {
                findings.recordSkipped();
                continue;
            }

            int proxiedStatus = proxied.response().statusCode();
            if (proxiedStatus == 421 || proxiedStatus == 429 || (Utilities.globalSettings.getBoolean("mining: filter 500s") && proxiedStatus >= 500 && proxiedStatus != 525)) {
                findings.recordSkipped();
                continue;
            }

            // if matches the invalid-dns response, skip it
            if (randomSubGroup.matches(proxied) || (subdomain.contains(".") && nestedSubGroup.matches(proxied))) {
                findings.recordSkipped();
                continue;
            }

            boolean skip = false;
            for (CustomResponseGroup group: validSubGroups) {
                if (group.matches(proxied)) {
                    skip = true;
                    break;
                }
            }

            if (skip) {
                findings.recordSkipped();
                continue;
            }


            if (proxied.response().contains("DNS points to local or disallowed IP", true) ||
                    proxied.response().contains("You don't have permission to access \"", true) ||
                    proxied.response().contains("The requested URL \"&#91;no&#32;URL&#93;\", is invalid.", true) ||
                    proxied.response().contains("CNAME Cross-User Banned | Cloudflare", true)) {
                continue;
            }

            validSubGroups.add(new CustomResponseGroup(Lensmine::calculateFingerprint, proxied));

            if (proxied.response().isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION) && getRedirPathIfSameOrigin(proxied) == null) {
                continue;
            }

            HttpService directService = HttpService.httpService(fullDomain, service.getPort(), service.getPort() == 443);
            HttpRequestResponse direct = null;
            try {
                HttpRequest directRequest = HttpRequest.httpRequest(directService, ByteArray.byteArray(attackReq));
                direct = Utilities.montoyaApi.http().sendRequest(directRequest);
            } catch (RuntimeException e) {
                Utilities.out("Can't direct access "+fullDomain);
            }

            if (direct == null || !direct.hasResponse()) {
                proxied = resolveRedirect(proxied);
                if (proxied.response().isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)) {
                    continue;
                }
                findings.add(new AccessPair(proxied, direct, Arrays.asList("response")));
                sendToOrganiser(proxied, service.getHost() + " | proxied  | access");
                maxDomainsToCheck += 1000;
                continue;
            }

            if (proxied.response().isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)) {
                proxied = resolveRedirect(proxied);

                if (proxied.response().isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)) {
                    continue;
                }
                direct = resolveRedirect(direct);
            }

            // if the direct response doesn't match the indirect response, report it
            CustomResponseGroup proxiedGroup = new CustomResponseGroup(Lensmine::calculateFingerprint, proxied);
            if (proxiedGroup.matches(direct)) {
                continue;
            }

            maxDomainsToCheck += 100;

            ArrayList<String> diffKeys = proxiedGroup.diffKeys(direct);
            String notes = "";

            // if there's any headers missing from the proxied request, we might be bypassing a different proxy
            if (diffKeys.size() == 1) {
                if (diffKeys.contains("headers")) {
                    List<String> proxiedHeaderNames = proxied.response().headers().stream().map(HttpHeader::name).map(String::toLowerCase).toList();
                    List<String> missingHeaderNames = direct.response().headers().stream().map(HttpHeader::name).map(String::toLowerCase).filter(name -> !proxiedHeaderNames.contains(name)).toList();
                    LinkedList<String> interestingHeaderNames = new LinkedList<>(missingHeaderNames);
                    interestingHeaderNames.remove("content-length");
                    interestingHeaderNames.remove("age");
                    interestingHeaderNames.remove("x-cache");
                    interestingHeaderNames.remove("set-cookie");
                    interestingHeaderNames.remove("connection");
                    interestingHeaderNames.remove("accept-ranges");
                    interestingHeaderNames.remove("etag");
                    interestingHeaderNames.remove("alt-svc");
                    if (interestingHeaderNames.isEmpty()) {
                        continue;
                    }
                    notes = interestingHeaderNames.toString();
                }

                if (diffKeys.contains("location")) {
                    String location = proxied.response().headerValue("Location");
                    String hostHeader = proxied.request().headerValue(Lenscrack.TARGETHEADER);
                    if (!location.startsWith("/") && !location.startsWith("http://"+hostHeader+"/") && !location.startsWith("https://"+hostHeader+"/")) {
                        continue;
                    }
                }
            }

            sendToOrganiser(proxied, service.getHost() + " | proxied  | " + diffKeys);
            sendToOrganiser(direct, service.getHost() + " | direct | " + diffKeys);

            findings.add(new AccessPair(proxied, direct, diffKeys, notes));
        }

        return findings;
    }

    static void sendToOrganiser(HttpRequestResponse resp, String notes) {
        resp.annotations().setNotes("v2.2"+notes);
        Utilities.montoyaApi.organizer().sendToOrganizer(resp);
    }

    static HttpRequestResponse resolveRedirect(HttpRequestResponse resp) {
        Utilities.out("Resolving redirect on "+resp.request().httpService().host() +"/"+resp.request().headerValue("Host"));
        for (int i=0; i<4; i+=1) {

            String path = getRedirPathIfSameOrigin(resp);
            if (path == null) {
                break;
            }

            HttpRequestResponse temp = Utilities.montoyaApi.http().sendRequest(resp.request().withPath(path));
            if (!temp.hasResponse()) {
                break;
            }

            resp = temp;
        }
        return resp;
    }

    static String getRedirPathIfSameOrigin(HttpRequestResponse resp) {
        if (!resp.response().isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION) || !resp.response().hasHeader("Location")) {
            return null;
        }

        String location = getLocation(resp).replace("https", "http");

        // don't follow redirects to the 'real' domain
        // && !location.startsWith("http://"+resp.httpService().host())
        if (!location.startsWith("/")  && !location.startsWith("http://"+resp.request().headerValue("Host"))) {
            return null;
        }

        String path = location;
        if (!location.startsWith("/")) {
            try {
                path = new URL(location).getPath(); // loses the query string
                // path = "/"+location.split("/", 4)[3];
            } catch (MalformedURLException e) {
                return null;
            }

        }

        if ("/".equals(path)) {
            return null;
        }
        return path;
    }




    static MineFindings doScan(byte[] baseReq, IHttpService service, int domainsToCheck) {
        baseReq = Utilities.setBody(baseReq, "");
        baseReq = Utilities.setMethod(baseReq, "GET");
        baseReq = Utilities.setPath(baseReq, "/"); // does this make sense?
        baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Length", "0");
        String tpd = InternetDomainName.from(service.getHost()).topPrivateDomain().toString();
        MineFindings findings = null;
        try {
            findings = Lensmine.mineSubdomains(baseReq, service, tpd, domainsToCheck);
        } catch (Exception e) {
            Utilities.out(e.toString());
            e.printStackTrace();
        }

        return findings;
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        MineFindings findings = doScan(baseReq, service, 100);
        if (findings != null) {
            String report = findings.findingsToString();
            Resp req = request(service, baseReq);
            report("Direct-mined domains: "+findings.getTitle(), report, baseReq, req);
        }
        return null;
    }

    static String getData(HttpRequestResponse resp) {
        String data = getLocation(resp);
        if (data == null) {
            try {
                data = getTitle(resp);
            } catch (Exception e) {
                data = "";
            }
        }

        return StringUtils.abbreviate(data, 48);
    }

    static String getLocation(HttpRequestResponse resp) {
        return resp.response().headerValue("Location");
    }

    static String getTitle(HttpRequestResponse resp) {
        try {
            String body = resp.response().bodyToString();
            if (!body.contains("<title")) {
                return "";
            }
            return body.split("<title", 1)[1].split(">", 1)[1].split("<")[0];
        } catch (Exception e) {
            return "";
        }
    }

    static HashMap<String, Object> calculateFingerprint(HttpRequestResponse resp) {
        HashMap<String, Object> fingerprint = new HashMap<>();

        if (!resp.hasResponse()) {
            fingerprint.put("status", 0);
            return fingerprint;
        }

        fingerprint.put("status", resp.response().statusCode());
        //fingerprint.put("version", resp.response().httpVersion());
        fingerprint.put("headers", resp.response().headers().stream().map(HttpHeader::name).sorted().toList());
        fingerprint.put("title", getTitle(resp));
        String location  = "";
        if (resp.response().hasHeader("Location")) {
            location = resp.response().headerValue("Location").replace("https", "http").split("[?]")[0];
            if (location.startsWith("http")) {
                //location = location.replace("http://"+resp.httpService().host(), "");
                location = location.replace("http://"+resp.request().headerValue(Lenscrack.TARGETHEADER), "");
            }
        }
        fingerprint.put("location", location);

        return fingerprint;
    }

    static HashMap<String, Object> statusPrint(HttpRequestResponse resp) {
        HashMap<String, Object> fingerprint = new HashMap<>();
        fingerprint.put("status", resp.response().statusCode());
        return fingerprint;
    }
}

class AccessPair {
    HttpRequestResponse left;
    HttpRequestResponse right;

    public String notes = "";

    List<String> diffKeys;

    public AccessPair(HttpRequestResponse left, HttpRequestResponse right, List<String> diffKeys) {
        this(left, right, diffKeys, "");
    }
    public AccessPair(HttpRequestResponse left, HttpRequestResponse right, List<String> diffKeys, String notes) {
        this.left = left;
        this.right = right;
        this.diffKeys = diffKeys;
        this.notes = notes;
    }

    public HttpRequestResponse getLeft() {
        return left;
    }

    public HttpRequestResponse getRight() {
        return right;
    }

    public List<String> getDiffKeys() {
        return diffKeys;
    }

    public int getDiffScore() {
        int base = 0;
        if (left.hasResponse() && (right == null || !right.hasResponse())) {
            base += 100;
        }
        base +=  diffKeys.size() * 10;
        base += 9 - (left.response().statusCode() / 100);
        return base;
    }
}


class MineFindings {
    ArrayList<AccessPair> findings;
    int skipped = 0;

    public MineFindings() {
        findings = new ArrayList<>();
    }

    void add(AccessPair finding) {
        findings.add(finding);
    }

    void recordSkipped() {
        skipped += 1;
    }

    String getTitle() {
        StringBuilder title = new StringBuilder();
        title.append(findings.size());
        title.append("/");
        title.append(skipped);
        return title.toString();
    }

    String findingsToString() {
        if (findings.isEmpty()) {
            return "";
        }

        StringBuilder detail = new StringBuilder();

        findings.sort(Comparator.comparingInt(a -> a.getDiffScore()*-1));

        detail.append("====");
        detail.append(getTitle());
        detail.append("====");
        detail.append("<br/>");
        // todo condense matching responses

        detail.append("<table>");
        detail.append("<tr><td>Access</td><td>Host</td><td>Status</td><td>Length</td><td>Diffkeys</td><td>Time</td><td>Data</td><td>Notes</td></tr>");
        for (AccessPair finding: findings) {
            detail.append("<tr><td>");
            detail.append("Proxied</td><td>");
            detail.append(finding.getLeft().request().headerValue(Lenscrack.TARGETHEADER));
            detail.append("</td><td>");
            detail.append(finding.getLeft().response().statusCode());
            detail.append("</td><td>");
            detail.append(finding.getLeft().response().toString().length());
            detail.append("</td><td>");
            detail.append(String.join(", ", finding.diffKeys));
            detail.append("</td><td>");
            detail.append(finding.getLeft().timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis());
            detail.append("</td><td>");
            detail.append(Lensmine.getData(finding.getLeft()));
            detail.append("</td><td>");
            detail.append(finding.notes);
            detail.append("</td></tr>");

            //responses.add(new Resp(finding.getLeft()));

            if (finding.getRight() != null && finding.getRight().hasResponse() ) {
                detail.append("<tr><td>");
                detail.append("Direct</td><td>");
                detail.append(finding.getRight().request().headerValue(Lenscrack.TARGETHEADER));
                detail.append("</td><td>");
                detail.append(finding.getRight().response().statusCode());
                detail.append("</td><td>");
                detail.append(finding.getRight().response().toString().length());
                detail.append("</td><td>");

                detail.append("</td><td>");
                detail.append(finding.getRight().timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis());
                detail.append("</td><td>");
                detail.append(Lensmine.getData(finding.getRight()));
                detail.append("</td></tr>");
                //responses.add(new Resp(finding.getRight()));
            }

            detail.append("<tr><td></td><td></td><td></td><td></td></tr>");
        }

        detail.append("</table>");
        return detail.toString();
    }
}
