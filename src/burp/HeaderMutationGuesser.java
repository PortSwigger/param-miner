package burp;

import burp.model.utilities.Utilities;
import burp.view.ConfigurableSettings;
import burp.albinowaxUtils.CustomScanIssue;
import burp.albinowaxUtils.HeaderMutator;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class HeaderMutationGuesser {
    private ConfigurableSettings config;
    private byte[] req;
    private IHttpService service;
    public HashMap<String, IHttpRequestResponse[]> evidence;
    private String[][] testHeaders;
    private URL url;

    HeaderMutationGuesser(IHttpRequestResponse req, ConfigurableSettings config, Utilities utilities) {
      this.url       = utilities.getURL(req);
      this.req       = req.getRequest();
      this.utilities = utilities;
      if (utilities.isHTTP2(this.req)) {
            this.req = utilities.convertToHttp1(this.req);
        }
        this.config = config;
        this.service = req.getHttpService();
        this.evidence = new HashMap<String, IHttpRequestResponse[]>();

        this.testHeaders = new String[][]{
                {"Content-Length: 0", "Content-Length: z"}
        };
    }

    // Returns the mutation names used by HeaderMutator
    public ArrayList<String> guessMutations() {
        byte[] baseReq = this.removeHeader(this.req, "Content-Length");
        ArrayList<String> ret     = new ArrayList<String>();
        HeaderMutator     mutator = new HeaderMutator(utilities);

        // Test all the mutations to find back-end errors
        for (int i = 0; i< this.testHeaders.length; i++) {
            Iterator<String> iterator = mutator.mutations.iterator();
            String testHeaderValid = this.testHeaders[i][0];
            String testHeaderInvalid = this.testHeaders[i][1];

            // Get the front-end error
            IHttpRequestResponse frontErrReq = this.requestHeader(baseReq, testHeaderInvalid);
            byte[] frontError = frontErrReq.getResponse();

            // Check we've managed to generate an error
            IHttpRequestResponse noErrReq = this.requestHeader(baseReq, testHeaderValid);
            byte[] noErr = noErrReq.getResponse();
            if (this.requestMatch(frontError, noErr)) {
                continue;
            }

            if (frontError == null || noErr == null || frontError.length == 0 || noErr.length == 0) {
                String host = frontErrReq.getHttpService().getHost();
                utilities.out("Failed to fetch request while guessing mutations " + host);
                continue;
            }

            while (iterator.hasNext()) {
                String mutation = iterator.next();
                if (ret.contains(mutation)) {
                    continue;
                }
                byte[] mutated = mutator.mutate(testHeaderInvalid, mutation);
                IHttpRequestResponse testReqResp = this.requestHeader(baseReq, mutated);
                byte[] testReq = testReqResp.getResponse();

                if (testReq == null) {
                    String host = testReqResp.getHttpService().getHost();
                    utilities.out("Failed to send request to host " + host + " using mutation " + mutation + " using junk value");
                    continue;
                }

                // Check that:
                //  1. We have a different error than the front-end error
                //  2. We have an error at all (i.e. not the same as the base request
                // In this case, confirm that we get no error (i.e. the base response) with mutation(CL: 0)
                if (!this.requestMatch(frontError, testReq) && !this.requestMatch(noErr, testReq)) {
                    mutated = mutator.mutate(testHeaderValid, mutation);
                    IHttpRequestResponse validReqResp = this.requestHeader(baseReq, mutated);
                    byte[] validResp = validReqResp.getResponse();
                    if (validResp == null) {
                        String host = validReqResp.getHttpService().getHost();
                        utilities.out("Failed to send request to host " + host + " using mutation " + mutation + " with valid value");
                    }
                    if (this.requestMatch(noErr, validResp)) {
                        ret.add(mutation);
                        IHttpRequestResponse[] reqs = new IHttpRequestResponse[4];
                        reqs[0] = frontErrReq;
                        reqs[1] = noErrReq;
                        reqs[2] = testReqResp;
                        reqs[3] = validReqResp;
                        this.evidence.put(mutation, reqs);
                    }
                }
            }
        }

        // TODO: Maybe re-check mutations to deal with inconsistent servers?
        return ret;
    }

    public void reportMutations(ArrayList<String> mutations) {
        Iterator<String> iterator = mutations.iterator();
        while (iterator.hasNext()) {
            String mutation = iterator.next();
            utilities.out("Found mutation against " + this.url + ": " + mutation);
            IHttpRequestResponse[] evidence = this.evidence.get(mutation);
            IHttpService service = evidence[0].getHttpService();
            utilities.callbacks.addScanIssue(new CustomScanIssue(
                    service,
                    utilities.helpers.analyzeRequest(service, evidence[0].getRequest()).getUrl(),
                    evidence,
                    "Header mutation found",
                    "Headers can be snuck to a back-end server using the '" + mutation + "' mutation.",
                    "Information",
                    "Firm",
                    "This issue is not exploitable on its own, but interesting headers may be able to be snuck through to backend servers."
            ));
        }
    }

private final Utilities utilities;

private IHttpRequestResponse requestHeader(byte[] baseReq, String header) {
        return this.requestHeader(baseReq, header.getBytes(StandardCharsets.UTF_8));
    }

    private IHttpRequestResponse requestHeader(byte[] baseReq, byte[] header) {
        byte[] req = this.addHeader(baseReq, header);
        req = utilities.addCacheBuster(req, utilities.generateCanary());
        return utilities.attemptRequest(this.service, req, true);
    }

    private byte[] removeHeader(byte[] req, String headerName) {
        int[] offsets = utilities.getHeaderOffsets(req, headerName);
        if (offsets == null) {
            return req;
        }
        int start = offsets[0];
        int end = offsets[2] + 2;
        byte[] ret = new byte[req.length - (end - start)];
        // TODO: sometimes getting null point exceptions from this line
        System.arraycopy(req, 0, ret, 0, start);
        System.arraycopy(req, end, ret, start, req.length - end);
        return ret;
    }

    private boolean requestMatch(byte[] resp1, byte[] resp2) {
        if (resp1 == null || resp2 == null) {
            return false;
        }

        IResponseInfo info1 = utilities.helpers.analyzeResponse(resp1);
        IResponseInfo info2 = utilities.helpers.analyzeResponse(resp2);
        if (info1.getStatusCode() != info2.getStatusCode()) {
            return false;
        }

        // If we have a body length, use that as a comparison. Otherwise, use the total length
        int length1 = resp1.length - info1.getBodyOffset();
        int length2 = resp2.length - info2.getBodyOffset();
        if (length1 == 0 || length2 == 0) {
            length1 = resp1.length;
            length2 = resp2.length;
        }
        int lower = (9 * length1) / 10;
        int upper = (11 * length1) / 10;

        if (length2 <= lower || length2 >= upper) {
            return false;
        }

        return true;
    }

    private byte[] addHeader(byte[] baseReq, byte[] header) {
        IRequestInfo info = utilities.analyzeRequest(baseReq);
        int offset = info.getBodyOffset() - 2;
        byte[] ret = new byte[baseReq.length + header.length + 2];
        byte[] crlf = "\r\n".getBytes(StandardCharsets.UTF_8);

        System.arraycopy(baseReq, 0, ret, 0, offset);
        System.arraycopy(header, 0, ret, offset, header.length);
        int newOffset = offset + header.length;
        System.arraycopy(crlf, 0, ret, newOffset, 2);
        newOffset += 2;
        System.arraycopy(baseReq, offset, ret, newOffset, baseReq.length - offset);

        return ret;
    }
}