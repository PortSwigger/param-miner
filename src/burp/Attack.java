package burp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * Created by james on 24/11/2016.
 */
class Attack {
    private IHttpRequestResponse firstRequest;
    private HashMap<String, Object> firstFingerprint;

    private final String[] keys = {"</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};
    String payload;
    private Probe probe;
    private String anchor;
    private HashMap<String, Object> fingerprint;

    private IResponseKeywords responseKeywords = Utilities.helpers.analyzeResponseKeywords(Arrays.asList(keys));
    private IResponseVariations responseDetails = Utilities.helpers.analyzeResponseVariations();
    private int responseReflections = -1;

    public Attack(IHttpRequestResponse req, Probe probe, String payload, String anchor) {
        this.firstRequest = req;
        this.probe = probe;
        this.payload = payload;
        this.anchor = anchor;
        add(req.getResponse(), anchor);
        firstFingerprint = fingerprint;
    }

    public Attack(IHttpRequestResponse req) {
        this.firstRequest = req;
        add(req.getResponse(), "");
        firstFingerprint = fingerprint;
    }

    public Attack() {}


    public HashMap<String, Object> getPrint() {
        return fingerprint;
    }

    public HashMap<String, Object> getFirstPrint() {
        return firstFingerprint;
    }

    public IHttpRequestResponse getFirstRequest() {
        return firstRequest;
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

    Probe getProbe() {
        return probe;
    }

    public Attack add(byte[] response, String anchor) {
        assert (firstRequest != null);


        response = Utilities.filterResponse(response);
        responseKeywords.updateWith(response);
        responseDetails.updateWith(response);

        if(!anchor.equals("")) {
            int reflections = -1;//Utilities.countMatches(response, anchor.getBytes());
            if (responseReflections == -1) {
                responseReflections = reflections;
            } else if (responseReflections != reflections) {
                responseReflections = -2;
            }
        }

        // print.put("Content start", Utilities.getStartType(response));

        regeneratePrint();

        return this;
    }

    // todo verify this actually works as intended
    Attack addAttack(Attack attack) {
        if(firstRequest == null) {
            firstRequest = attack.firstRequest;
            anchor = attack.anchor;
            probe = attack.getProbe();
            payload = attack.payload;
            add(attack.getFirstRequest().getResponse(), anchor);
            firstFingerprint = fingerprint;
        }
        //add(attack.firstRequest.getResponse(), anchor);
        HashMap<String, Object> generatedPrint = new HashMap<>();
        HashMap<String, Object> inputPrint = attack.getPrint();
        for (String key: inputPrint.keySet()) {
            if (fingerprint.containsKey(key)) {
                if (fingerprint.get(key).equals(inputPrint.get(key))) {
                    generatedPrint.put(key, fingerprint.get(key));
                }
            }
        }

        fingerprint = generatedPrint;
        return this;
    }

}
