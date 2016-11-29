package burp;

import org.apache.commons.lang3.StringEscapeUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;


public class TransformationScan {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public TransformationScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    private HashSet<String> getTransformationResults(String leftAnchor, String rightAnchor, byte[] response) {
        List<int[]> leftAnchorReflections = Utilities.getMatches(response, leftAnchor.getBytes(), -1);
        HashSet<String> results = new HashSet<>();
        for (int[] reflection_location : leftAnchorReflections) {
            byte[] reflection = Arrays.copyOfRange(response, reflection_location[1], reflection_location[1] + 20);
            List<int[]> matches = Utilities.getMatches(reflection, rightAnchor.getBytes(), -1);
            int reflection_end;
            if (matches.isEmpty()) {
                results.add("Truncated"); //+StringEscapeUtils.unescapeHtml4(helpers.bytesToString(Arrays.copyOfRange(reflection, 0, 8))));
            } else {
                reflection_end = matches.get(0)[0];
                results.add(StringEscapeUtils.unescapeHtml4(helpers.bytesToString(Arrays.copyOfRange(reflection, 0, reflection_end))));
            }
        }
        if (leftAnchorReflections.isEmpty()) {
            results.add("Reflection disappeared");
        }
        return results;
    }

    private HashSet<String> recordHandling(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String probe) {
        String leftAnchor = Utilities.randomString(3);
        String middleAnchor = "z"+Integer.toString(Utilities.rnd.nextInt(9));
        String rightAnchor = "z"+Utilities.randomString(3);
        String payload = leftAnchor + "\\\\" + middleAnchor + probe + rightAnchor;

        IHttpRequestResponse attack = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), insertionPoint.buildRequest(payload.getBytes())); // Utilities.buildRequest(baseRequestResponse, insertionPoint, payload)

        return getTransformationResults(leftAnchor + "\\" + middleAnchor, rightAnchor, helpers.stringToBytes(helpers.bytesToString(Utilities.filterResponse(attack.getResponse()))));
    }

    private Probe.ProbeResults classifyHandling(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String probe, boolean expectBackSlashConsumption) {
        Probe.ProbeResults classifiedTransformations = new Probe.ProbeResults();

        HashSet<String> noTransform = new HashSet<>();
        HashSet<String> backslashConsumed = new HashSet<>();

        HashSet<String> transformations = recordHandling(baseRequestResponse, insertionPoint, probe);
        for (String transform : transformations) {
            String pretty_transform = probe + " => " + transform;
            try {
                if (probe.startsWith("\\")) {
                    if (transform.equals(probe) || URLDecoder.decode(transform, "UTF-8").equals(probe)) {
                        noTransform.add(pretty_transform);
                    } else if (transform.equals(probe.substring(1))) {
                        backslashConsumed.add(pretty_transform);
                    } else {
                        classifiedTransformations.interesting.add(pretty_transform);
                    }

                } else {
                    if (transform.equals(probe) || URLDecoder.decode(transform, "UTF-8").equals(probe)) {
                        classifiedTransformations.boring.add(pretty_transform);
                    } else {
                        classifiedTransformations.interesting.add(pretty_transform);
                    }
                }
            }
            catch (UnsupportedEncodingException e) {
                classifiedTransformations.interesting.add(pretty_transform);
            }
        }

        if (expectBackSlashConsumption) {
            classifiedTransformations.boring.addAll(backslashConsumed);
            classifiedTransformations.interesting.addAll(noTransform);
        } else {
            classifiedTransformations.boring.addAll(noTransform);
            classifiedTransformations.interesting.addAll(backslashConsumed);
        }

        return classifiedTransformations;
    }

    public IScanIssue findTransformationIssues(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        String leftAnchor = Utilities.randomString(5);
        String rightAnchor = "z" + Utilities.randomString(2);
        Attack basicAttack = Utilities.buildTransformationAttack(baseRequestResponse, insertionPoint, leftAnchor, "\\\\", rightAnchor);
        if (Utilities.getMatches(Utilities.filterResponse(basicAttack.getFirstRequest().getResponse()), (leftAnchor + "\\" + rightAnchor).getBytes(), -1).isEmpty()) {
            return null;
        }

        HashSet<String> default_behaviour = recordHandling(baseRequestResponse, insertionPoint, "\\zz");

        // assumes only one backslash-eating reflection
        boolean backslashConsumed = false;
        if (default_behaviour.contains("zz")) {
            backslashConsumed = true;
        }

        ArrayList<String> interesting = new ArrayList<>();
        ArrayList<String> boring = new ArrayList<>();

        String[] decodeBasedPayloads = {"101", "x41", "u0041", "0", "1", "x0"};
        String[] payloads = {"'", "\"", "{", "}", "(", ")", "[", "]", "$", "`", "/", "@", "#", ";", "%", "&", "|", ";", "^", "?"};

        for (String payload : decodeBasedPayloads) {
            Probe.ProbeResults handling = classifyHandling(baseRequestResponse, insertionPoint, "\\" + payload, backslashConsumed);
            interesting.addAll(handling.interesting);
            boring.addAll(handling.boring);
        }

        for (String payload : payloads) {

            String escaped_payload = "\\" + payload;
            String chosen_payload, followUpPayload;
            if (backslashConsumed) {
                chosen_payload = payload;
                followUpPayload = escaped_payload;
            } else {
                chosen_payload = escaped_payload;
                followUpPayload = payload;
            }

            Probe.ProbeResults handling = classifyHandling(baseRequestResponse, insertionPoint, chosen_payload, backslashConsumed);
            if (!handling.interesting.isEmpty()) {
                interesting.addAll(handling.interesting);

                HashSet<String> followUpTransforms = recordHandling(baseRequestResponse, insertionPoint, followUpPayload);
                for (String transform : followUpTransforms) {
                    interesting.add(followUpPayload + " => " + transform);
                }
            }

            boring.addAll(handling.boring);
        }

        // IHttpRequestResponse highlightedAttack = Utilities.highlightRequestResponse(attack, expect, probe, insertionPoint);
        return (new InputTransformation(interesting, boring, basicAttack.getFirstRequest(), helpers.analyzeRequest(baseRequestResponse).getUrl(), insertionPoint.getInsertionPointName()));
    }
}
