package burp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * Created by james on 24/11/2016.
 */
class Attack {
    public IHttpRequestResponse req;

    private final String[] keys = {"</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};
    String payload;
    private Probe probe;
    private String anchor;
    private HashMap<String, Object> fingerprint;

    private IResponseKeywords responseKeywords = Utilities.helpers.analyzeResponseKeywords(Arrays.asList(keys));
    private IResponseVariations responseDetails = Utilities.helpers.analyzeResponseVariations();
    private int responseReflections = -1;

    public Attack(IHttpRequestResponse req, Probe probe, String payload, String anchor) {
        this.req = req;
        this.probe = probe;
        this.payload = payload;
        this.anchor = anchor;
        add(req.getResponse(), anchor);
    }

    public HashMap<String, Object> getPrint() {
        return fingerprint;
    }

    private void regeneratePrint() {
        HashMap<String, Object> generatedPrint = new HashMap<>();
        List<String> keys = responseKeywords.getInvariantKeywords();
        for (String key : keys) {
            generatedPrint.put(key, responseKeywords.getKeywordCount(key, 0));
        }

        keys = responseDetails.getInvariantAttributes();
        for (String key : keys) {
            generatedPrint.put(key, responseDetails.getAttributeValue(key, 0));

        }

        if (responseReflections > -1) {
            generatedPrint.put("input_reflections", responseReflections);
        }

        fingerprint = generatedPrint;
    }

    public Probe getProbe() {
        return probe;
    }

    public Attack add(byte[] response, String anchor) {
        assert (req != null);

        response = Utilities.filterResponse(response);
        responseKeywords.updateWith(response);
        responseDetails.updateWith(response);

        int reflections = Utilities.countMatches(response, anchor.getBytes());
        if (responseReflections == -1) {
            responseReflections = reflections;
        } else if (responseReflections != reflections) {
            responseReflections = -2;
        }

        // print.put("Content start", Utilities.getStartType(response));

        regeneratePrint();

        return this;
    }

    public Attack addAttack(Attack attack) {
        add(attack.req.getResponse(), anchor);
        return this;
    }

}
