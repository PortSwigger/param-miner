package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.HashMap;

import static burp.Scan.request;


public class ProxyServer {

    boolean badTarget = false;
    HttpRequest baseReq;
    MontoyaRequestResponse baseline;
    HashMap<InjectionType, ProxyProbe> baseProbes = new HashMap<>();


    public ProxyServer(IHttpRequestResponse baseRequestResponse) {
        baseReq = Utilities.buildMontoyaReq(Utilities.convertToHttp1(baseRequestResponse.getRequest()), baseRequestResponse.getHttpService());

        // strip prior attacks
        for (HttpHeader header : baseReq.headers()) {
            if (header.toString().length() > 1000 || header.name().equals("A-Wrap")) {
                baseReq = baseReq.withRemovedHeader(header.name());
            }
        }

        baseReq = baseReq.withParameter(HttpParameter.urlParameter("cb", Utilities.randomString(8))).withAddedHeader("A-Wrap", "foo");
        baseline = request(baseReq, true);
        if (!baseline.hasResponse()) {
            badTarget = true;
            return;
        }
    }

    private void confirmServerLimit(ProxyProbe baseAppendProbe) {
        ProxyProbe alteredProbe = new ProxyProbe(HttpHeader.httpHeader(baseAppendProbe.getHeader().name()+"AAAA", baseAppendProbe.getHeader().value()+"BBBBB"), baseAppendProbe);
        MontoyaRequestResponse testName = alteredProbe.probe(baseAppendProbe.getSizeLimit());
        if (testName.status() != baseline.status()) {
            baseAppendProbe.setSizeAdjustment(baseAppendProbe.getHeader().name().length());
        }

        ProxyProbe asdf = new ProxyProbe(HttpHeader.httpHeader(baseAppendProbe.getHeader().name(), baseAppendProbe.getHeader().value()), baseAppendProbe);
        if (asdf.probe(-1).status() == asdf.probe(0).status()) {
            badTarget = true;
            return;
        }

        for (int i=1; i<7; i++) {
            String header = "X-Y"+Utilities.randomString(i *2) + ": "+ Utilities.randomString(i);
            ProxyProbe prober = new ProxyProbe(HttpHeader.httpHeader(header.split(":")[0], header.split(": ")[1]), baseAppendProbe);

            MontoyaRequestResponse tooSmall = prober.probe(-1);
            MontoyaRequestResponse tooBig = prober.probe(0);
            if (tooSmall.status() == tooBig.status() || tooSmall.status() != baseline.status()) {
                badTarget = true;
                return;
            }
        }
    }

    private int getMax(ProxyProbe prober) {
        int MAX_REQUESTS = 100;
        int current = 50;
        int min = 1;
        int max = 999999;

        for (int i=0; i<MAX_REQUESTS; i++) {
            if (max-min <= 1) {
                break;
            }

            MontoyaRequestResponse probe = prober.probe(current);
            if (probe.status() != baseline.status()) {
                max = current;
                current = min + (max - min) / 2;
            } else {
                min = current;
                current = min + (max - min) / 2;
            }
        }

        return max;
    }

    private void prepareProbe(ProxyProbe prober) {
        ProxyProbe baseProbe;
        if (baseProbes.containsKey(prober.getInjectionType())) {
            baseProbe = baseProbes.get(prober.getInjectionType());
        } else {
            baseProbe = new ProxyProbe(HttpHeader.httpHeader("X-Arbitrary", Utilities.randomString(1)), prober.getInjectionType());
            baseProbe.setBaseReq(baseReq);
            baseProbe.setSizeLimit(getMax(baseProbe));
            confirmServerLimit(baseProbe);
            baseProbes.put(prober.getInjectionType(), baseProbe);
        }

        prober.importSettings(baseProbe);
    }

    private static void classifyResult(ProxyTransformationResult transformationResult) {
        if (transformationResult.transformation == 0) {
            transformationResult.setResult(ProxyTransformationResult.INCONSISTENT);
        } else if (transformationResult.transformation < 0) {
            if (transformationResult.justOver == null) {
                transformationResult.transformation = -99999;
                transformationResult.setResult(ProxyTransformationResult.OVERWRITE);
            } else {
                transformationResult.setResult(ProxyTransformationResult.SHRINK);
            }
        } else {
            if (transformationResult.justUnder == null) {
                transformationResult.transformation = 99999;
                transformationResult.setResult(ProxyTransformationResult.BLOCKED);
            } else {
                transformationResult.setResult(ProxyTransformationResult.EXPAND);
            }

        }
    }

    public ProxyTransformationResult analyseTransformation(ProxyProbe prober) {

        if (badTarget) return null;
        prepareProbe(prober);
        MontoyaRequestResponse localBaseline = prober.probe(-prober.getSizeLimit());

        int MAX_REQUESTS = 100;
        int current = prober.getPad();
        int min = prober.getPad()-32; // was 0
        int max = prober.getPad()+32; // was +500

        // handle the simple case where there's no transformation
        // no repeats/confirmation required because it's not interesting anyway
        ProxyTransformationResult transformationResult = new ProxyTransformationResult(prober);
        MontoyaRequestResponse quickProbeL = prober.probe(-1);
        MontoyaRequestResponse quickProbeR = prober.probe(0);
        if (quickProbeL.status() != quickProbeR.status()) {
            transformationResult.transformation = 0;
            transformationResult.justOver = quickProbeR;
            transformationResult.justUnder = quickProbeL;
            transformationResult.setResult(ProxyTransformationResult.NO_CHANGE);
            return transformationResult;
        }

        // either there's a transformation, or the server is inconsistent
        for (int i = 0; i < MAX_REQUESTS; i++) {
            if (max - min == 1) {
                break;
            }

            MontoyaRequestResponse probe = prober.probe(current - prober.getPad());
            if (probe.status() != localBaseline.status()) {
                max = current;
                current = min + (max - min) / 2;
                transformationResult.justOver = probe;
            } else {
                min = current;
                current = min + (max - min) / 2;
                transformationResult.justUnder = probe;
            }
        }

        transformationResult.transformation = prober.getPad() - max;

        classifyResult(transformationResult);
        if (transformationResult.getResult() == ProxyTransformationResult.INCONSISTENT) {
            return transformationResult;
        }

        if (localBaseline.status() != baseline.status() && transformationResult.consistentCode()) {
            transformationResult.setResult(ProxyTransformationResult.BLOCKED);
            return transformationResult;
        }

        for (int i = 1; i < 12; i++) {
            if (!transformationResult.consistentCode()) {
                int offset = transformationResult.transformation * -1;
                MontoyaRequestResponse lprobe = prober.probe(offset - 1);
                MontoyaRequestResponse rprobe = prober.probe(offset);
                if (lprobe.status() == rprobe.status()) {
                    transformationResult.setResult(ProxyTransformationResult.INCONSISTENT);
                    return transformationResult;
                }
            } else {
                // todo are confirmations required for header removal too?
            }
        }

        transformationResult.valueIsRelevant = true;
        // check if the value is actually relevant - only applied to NAME_APPEND
        if ("X-Arbitrary".equals(prober.getHeader().name()) || (prober.getInjectionType() != InjectionType.NAME_APPEND && prober.getInjectionType() != InjectionType.NAME_PREPEND)) {
            transformationResult.valueIsRelevant = true;
        } else if (!"".equals(prober.getHeader().value())) {
            ProxyProbe defaultValueProber = new ProxyProbe(HttpHeader.httpHeader(prober.getHeader().name(), ""), prober);
            int offset = transformationResult.transformation * -1;
            MontoyaRequestResponse lprobe = defaultValueProber.probe(offset - 1);
            MontoyaRequestResponse rprobe = defaultValueProber.probe(offset);
            if (lprobe.status() == rprobe.status()) {
                transformationResult.valueIsRelevant = true;
            }
        }


        flagTruncation(transformationResult);

        return transformationResult;
    }

    private void flagTruncation(ProxyTransformationResult transformationResult) {
        try {
            HttpRequest req = transformationResult.justUnder.request();
            HttpRequest probe = req.withRemovedHeader("Host").withAddedHeader("Host", req.headerValue("Host"));
            int status = request(probe, true).status();
            if (status != transformationResult.justUnder.status()) {
                transformationResult.setResult(ProxyTransformationResult.TERMINATED);
            }
        } catch (Exception ignored) {

        }
    }

}
