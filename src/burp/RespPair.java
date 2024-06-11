package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class RespPair {
    HttpRequestResponse slowResp = null;
    HttpRequestResponse fastResp = null;

    Duration fastTime = Duration.ZERO;
    Duration slowTime = Duration.ZERO;

    boolean timingDiff = false;
    boolean codeDiff = false;
    boolean seenMatchingResponse = false;

    long closestTimingDiff = 1000;

    String timingData = "";

    protected int iterations;

    RespPair(byte[] slowBytes, byte[] fastBytes, IHttpService service) {
        this(slowBytes, fastBytes, service, false);
    }

    RespPair(byte[] slowBytes, byte[] fastBytes, IHttpService service, boolean ignoreTime) {
        QuantitativeMeasurements slowTimes = new QuantitativeMeasurements("time");
        QuantitativeMeasurements fastTimes = new QuantitativeMeasurements("time");
        OrderBox orders = new OrderBox();
        CustomResponseGroup slowGroup = new CustomResponseGroup(Lensmine::calculateFingerprint); // calculateFingerprint

        boolean mightGetTimingDiff = true;
        boolean mightGetCodeDiff = true;
        boolean http2 = false;
        int throttle = Utilities.globalSettings.getInt("per-thread throttle");

        int minSamplesBeforeBail = 2;
        int minSamplesBeforeCodeReport = 5;
        int minSamplesBeforeTimeReport = 100;
        if (ignoreTime) {
            minSamplesBeforeBail = 0;
        }

        for (iterations = 0; iterations < Math.max(minSamplesBeforeCodeReport, minSamplesBeforeTimeReport); iterations++) {

            if (Utilities.unloaded.get()) {
                break;
            }

            if (!mightGetCodeDiff && !mightGetTimingDiff) {
                break;
            }

            if (!mightGetCodeDiff && ignoreTime) {
                break;
            }

            if (mightGetCodeDiff && iterations >= minSamplesBeforeCodeReport) {
                break;
            }

            // did the underlying API break?!
            HttpRequest slowReq = Utilities.buildMontoyaReq(Utilities.replace(slowBytes, "$canary", Utilities.generateCanary()), service);
            HttpRequest fastReq = Utilities.buildMontoyaReq(Utilities.replace(fastBytes, "$canary", Utilities.generateCanary()), service);
            List<HttpRequest> reqList = new ArrayList<>();

            if (iterations % 2 == 0) {
                reqList.add(slowReq);
                reqList.add(fastReq);
                List<HttpRequestResponse> responses = sendSyncedRequests(reqList);
                slowResp = responses.get(0);
                fastResp = responses.get(1);
            } else {
                reqList.add(fastReq);
                reqList.add(slowReq);
                List<HttpRequestResponse> responses = sendSyncedRequests(reqList);
                slowResp = responses.get(1);
                fastResp = responses.get(0);
            }

            // if both requests failed, bail
            if ((!slowResp.hasResponse() || slowResp.response().statusCode() == 0) &&
                    (!fastResp.hasResponse() || fastResp.response().statusCode() == 0)) {
                return;
            }

            slowGroup.add(slowResp);

            // if one request failed, don't both with timing analysis
            if ((!slowResp.hasResponse() || slowResp.response().statusCode() == 0) || (!fastResp.hasResponse() || fastResp.response().statusCode() == 0)) {
                continue;
            }

            if (knownFalsePositive(slowResp, fastResp)) {
                return; // fixme is this causing FPs somehow? hmmmm shouldnt' be.
            }

            http2 = "HTTP/2".equals(slowResp.response().httpVersion());

            // ok, we've got two whole responses
            fastTime = fastResp.timingData().get().timeBetweenRequestSentAndStartOfResponse();
            slowTime = slowResp.timingData().get().timeBetweenRequestSentAndStartOfResponse();
            fastTimes.updateWith(new Resp(new Req(fastResp), 0, fastTime.toMillis()));
            slowTimes.updateWith(new Resp(new Req(slowResp), 0, slowTime.toMillis()));
            long timeGap = slowTime.toMillis() - fastTime.toMillis();
            orders.record(slowTime.toNanos() > fastTime.toNanos());
            if (timeGap < closestTimingDiff) {
                closestTimingDiff = timeGap;
            }

            if (mightGetCodeDiff && (slowGroup.badFingerprint() || slowGroup.matches(fastResp))) {
                mightGetCodeDiff = false;
            }

            if (iterations > minSamplesBeforeBail) {
                if (mightGetTimingDiff && (http2 || fastTimes.equals(slowTimes)) && (!http2 || !orders.consistent())) {
                    mightGetTimingDiff = false;
                }
            }

            Utilities.sleep(throttle);
        }


        if (mightGetCodeDiff && iterations >= minSamplesBeforeCodeReport) {
            codeDiff = true;
        }

        if (mightGetTimingDiff && iterations >= minSamplesBeforeTimeReport) {
            timingDiff = true;
            if (!fastTimes.equals(slowTimes)) {
                timingData += slowTimes.quantileRange() + "<<>>" + fastTimes.quantileRange() + "<br/>\n";
            }

            if (orders.consistent()) {
                timingData += orders.showData();
            }

        }
    }


    static List<HttpRequestResponse> sendSyncedRequests(List<HttpRequest> reqList) {
        return Utilities.montoyaApi.http().sendRequests(reqList);
//        boolean useSpike = Utilities.globalSettings.getBoolean("use turbo");
//
//        // fixme don't attempt spike for HTTP/1.1!
//        if (!useSpike) {
//            return Utilities.montoyaApi.http().sendRequests(reqList);
//        }
//
//        return TurboLib.requestGroup(reqList);
    }

    static boolean knownFalsePositive(HttpRequestResponse slowResp, HttpRequestResponse fastResp) {
        // Akamai
        String server = "";
        if (slowResp.response().hasHeader("Server")) {
            server = slowResp.response().headerValue("Server").toLowerCase();
        }

        if ("akamaighost".equals(server) && (
                slowResp.response().contains("The requested URL \"", true) ||
                        slowResp.response().contains("You don't have permission to access \"", true))
        ) {
            return true;
        }

        short slowStatus = slowResp.response().statusCode();
        short fastStatus = fastResp.response().statusCode();

        if ((slowStatus == 421 && fastStatus == 403) || (slowStatus == 403 && fastStatus == 421)) {
            if (slowResp.response().headers().size() < 9 && fastResp.response().headers().size() < 9 && ("cloudflare".equals(server) || "cloudfront".equals(server))) {
                return true;
            }
        }

        return false;
    }
}

class OrderBox {
    double left_first = 0;
    double right_first = 0;

    String showData() {
        return (Math.abs(left_first) + "/" + Math.abs(right_first) + " || " + compare());
    }

    private double compare() {
        return 1 - (Math.min(left_first, right_first) / (left_first+right_first)*2);
    }

    void record(boolean result) {
        if (result) {
            left_first += 1;
        } else {
            right_first += 1;
        }
    }

    boolean consistent() {
        return compare() > 0.5; // changed from 0.25 to 0.35 to cast wider net
    }
}