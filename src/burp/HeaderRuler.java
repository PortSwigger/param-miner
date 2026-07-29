package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * Follow-up probe run against headers Param Miner has discovered, using the "protocol ruler"
 * technique: the server's maximum header-size limit acts as a byte-count oracle. The header is
 * padded up to that size cliff, then a binary search finds where the cliff actually lands; the
 * delta between the expected and actual cliff position is the length of the transformation.
 *
 * Unlike the reflection-based checks in ValueProbes, this needs no observable response
 * difference, so it detects rewriting by front-ends that leave no trace in the response body.
 *
 * See https://portswigger.net/research/http-terminator#protocol-ruler
 */
public class HeaderRuler {

    private static final String REFERENCE = "\n\nReference: https://portswigger.net/research/http-terminator#protocol-ruler";

    static void probe(ParamAttack attack, String paramName) {
        if (!BulkUtilities.globalSettings.getBoolean("probe header transformations")) {
            return;
        }

        ProxyServer server = attack.getRuler();
        if (server == null) {
            return;
        }

        String headerName = paramName.split("~", 2)[0];

        for (ProxyProbe probe : buildProbes(headerName)) {
            ProxyTransformationResult result;
            try {
                result = server.analyseTransformation(probe);
            } catch (RuntimeException e) {
                BulkUtilities.out("Header ruler error on " + probe.getComment() + ": " + e);
                return;
            }

            // An unstable cliff makes every later measurement suspect, so retire the oracle for
            // the rest of this attack rather than emitting results we can't trust. badTarget is
            // checked too because confirmServerLimit can set it after analyseTransformation's
            // own entry check has already passed.
            if (result == null || result.getResult() == ProxyTransformationResult.INCONSISTENT || server.badTarget) {
                BulkUtilities.out("Retiring header ruler on " + attack.getTargetURL() + ": inconsistent result for " + probe.getComment());
                attack.disableRuler();
                return;
            }

            if (result.isInteresting()) {
                report(attack, result);
            }
        }
    }

    private static List<ProxyProbe> buildProbes(String headerName) {
        List<ProxyProbe> probes = new ArrayList<>();

        // is the header rewritten at all?
        probes.add(new ProxyProbe(HttpHeader.httpHeader(headerName, "wrtz"), InjectionType.VALUE_APPEND, headerName));

        // char-level probes: null byte and carriage return, wrapped as X-AAA…AAA-X
        probes.add(new ProxyProbe(HttpHeader.httpHeader(headerName, "X-AAA\0AAA-X"), InjectionType.VALUE_APPEND, headerName + " null-value"));
        probes.add(new ProxyProbe(HttpHeader.httpHeader(headerName, "X-AAA\rfoo:AAA-X"), InjectionType.VALUE_APPEND, headerName + " raw-r-value"));

        return probes;
    }

    private static void report(ParamAttack attack, ProxyTransformationResult result) {
        // wayUnder/wayOver are never populated by ProxyServer, and justOver is null for an
        // OVERWRITE, so only attach what actually exists
        List<HttpRequestResponse> evidence = new ArrayList<>();
        if (result.justUnder != null) {
            evidence.add(result.justUnder);
        }
        if (result.justOver != null) {
            evidence.add(result.justOver);
        }
        if (evidence.isEmpty()) {
            return;
        }

        String title = result.generateDescription();
        String detail = title + REFERENCE;

        for (HttpRequestResponse pair : evidence) {
            pair.annotations().setNotes("ext-reported: " + title + "\n\n" + detail);
            BulkUtilities.montoyaApi.organizer().sendToOrganizer(pair);
        }

        Scan.report(title, "<br/>" + detail.replaceAll("\n", "\n<br/>"),
                attack.getBaseRequestResponse().getRequest(),
                evidence.toArray(new HttpRequestResponse[0]));
    }
}
