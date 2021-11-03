package burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class MutationGuesser {
    private ConfigurableSettings config;
    private IHttpRequestResponse req;
    private ParamAttack attack;
    private IHttpService service;
    public HashMap<String, IHttpRequestResponse[]> evidence;
    private String[][] testHeaders;

    MutationGuesser(IHttpRequestResponse req, ParamAttack attack, ConfigurableSettings config) {
        this.req = req;
        this.attack = attack;
        this.config = config;
        this.service = this.attack.getBaseRequestResponse().getHttpService();
        this.evidence = new HashMap<String, IHttpRequestResponse[]>();

        this.testHeaders = new String[][]{
                {"Content-Length: 0", "Content-Length: z"},
                {"Range: bytes=0-", "Range: z"},
                {"Content-Type: application/x-www-form-urlencoded", "Content-Type: z"}
        };
    }

    // Returns the mutation names used by HeaderMutator
    public ArrayList<String> guessMutations() {
        byte[] baseReq = this.removeHeader(this.req.getRequest(), "Content-Length");
        ArrayList<String> ret = new ArrayList<String>();
        HeaderMutator mutator = new HeaderMutator();

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

            if (frontError.length == 0 || noErr.length == 0) {
                String host = frontErrReq.getHttpService().getHost();
                Utilities.out("Failed to fetch request while guessing mutations " + host);
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

                // Check that:
                //  1. We have a different error than the front-end error
                //  2. We have an error at all (i.e. not the same as the base request
                // In this case, confirm that we get no error (i.e. the base response) with mutation(CL: 0)
                if (!this.requestMatch(frontError, testReq) && !this.requestMatch(noErr, testReq)) {
                    mutated = mutator.mutate(testHeaderValid, mutation);
                    IHttpRequestResponse validReqResp = this.requestHeader(baseReq, mutated);
                    byte[] validResp = validReqResp.getResponse();
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

    private IHttpRequestResponse requestHeader(byte[] baseReq, String header) {
        return this.requestHeader(baseReq, header.getBytes(StandardCharsets.UTF_8));
    }

    private IHttpRequestResponse requestHeader(byte[] baseReq, byte[] header) {
        byte[] req = this.addHeader(baseReq, header);
        req = Utilities.addCacheBuster(req, Utilities.generateCanary());
        return Utilities.attemptRequest(this.service, req);
    }

    private byte[] removeHeader(byte[] req, String headerName) {
        int[] offsets = Utilities.getHeaderOffsets(req, headerName);
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
        IResponseInfo info1 = Utilities.helpers.analyzeResponse(resp1);
        IResponseInfo info2 = Utilities.helpers.analyzeResponse(resp2);
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
        IRequestInfo info = Utilities.analyzeRequest(baseReq);
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