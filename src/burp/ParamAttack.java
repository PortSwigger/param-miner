package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import java.util.*;

import static java.lang.Math.min;

class ParamAttack {

    CircularFifoQueue<String> recentParams;
    HashSet<String> alreadyReported;
    ArrayList<String> params;
    ArrayList<String> valueParams;
    int seed = -1;

    private WordProvider bonusParams;
    private HashMap<String, String> requestParams;
    private Deque<ArrayList<String>> paramBuckets;
    private int bucketSize;
    private IHttpRequestResponse baseRequestResponse;
    private PayloadInjector injector;
    private String attackID;
    private Attack base;
    private String targetURL;
    private Attack altBase;
    private boolean tryMethodFlip;
    private final ParamInsertionPoint insertionPoint;

    int getStop() {
        return stop;
    }

    private int stop;

    WordProvider getBonusParams() {
        return bonusParams;
    }

    HashMap<String, String> getRequestParams() {
        return requestParams;
    }

    String getTargetURL() {
        return targetURL;
    }

    ParamInsertionPoint getInsertionPoint() {
        return insertionPoint;
    }

    byte[] getInvertedBase() {
        return invertedBase;
    }

    private byte[] invertedBase;

    Attack getAltBase() {
        return altBase;
    }

    boolean shouldTryMethodFlip() {
        return tryMethodFlip;
    }

    Attack getBase() {
        return base;
    }

    String getAttackID() {
        return attackID;
    }

    PayloadInjector getInjector() {
        return injector;
    }

    Deque<ArrayList<String>> getParamBuckets() {
        return paramBuckets;
    }

    int getBucketSize() {
        return bucketSize;
    }

    IHttpRequestResponse getBaseRequestResponse() {
        return baseRequestResponse;
    }


    ParamAttack(IHttpRequestResponse baseRequestResponse, byte type, ParamGrabber paramGrabber, int stop) {
        this.stop = stop;
        this.baseRequestResponse = baseRequestResponse;
        targetURL = baseRequestResponse.getHttpService().getHost();
        params = ParamGuesser.calculatePayloads(baseRequestResponse, type, paramGrabber);
        valueParams = new ArrayList<>();
        for(int i = 0; i< params.size(); i++) {
            String candidate = params.get(i);
            if(candidate.contains("~")) {
                params.set(i, candidate.split("~", 2)[0]);
                if (!valueParams.contains(candidate)) {
                    valueParams.add(candidate);
                }
            }
        }

        // prevents attack cross-talk with stored input detection
        attackID = Utilities.mangle(Arrays.hashCode(baseRequestResponse.getRequest())+"|"+System.currentTimeMillis()).substring(0,2);

        requestParams = new HashMap<>();
        for (String entry: Keysmith.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>())) {
            String[] parsed = Keysmith.parseKey(entry);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }

        final String payload = ""; // formerly "<a`'\\\"${{\\\\"


        insertionPoint = getInsertionPoint(baseRequestResponse, type, payload, attackID);

        injector = new PayloadInjector(baseRequestResponse, insertionPoint);

        updateBaseline();

        //String ref = Utilities.getHeader(baseRequestResponse.getRequest(), "Referer");
        //HashMap<String, Attack> baselines = new HashMap<>();
        //baselines.put(ref, new Attack(baseRequestResponse));
        invertedBase = null;
        altBase = null;
        tryMethodFlip = false;

        int longest = params.stream().max(Comparator.comparingInt(String::length)).get().length();
        longest = min(20, longest);

        bucketSize = 16;
        if (type != IParameter.PARAM_URL) {
            bucketSize = 128;
        }

        StringBuilder basePayload = new StringBuilder();
        for (int i = 2; i < 16; i++) {
            basePayload.append("|");
            basePayload.append(Utilities.randomString(longest));
            if(i % 4 == 0) {
                base.addAttack(injector.probeAttack(basePayload.toString()));
            }
        }

        while (true) {
            Utilities.log("Trying bucket size: "+ bucketSize);
            StringBuilder trialPayload = new StringBuilder();
            trialPayload.append(Utilities.randomString(longest));
            for (int i = 0; i < bucketSize; i++) {
                trialPayload.append("|");
                trialPayload.append(Utilities.randomString(longest));
            }

            Attack trial = injector.probeAttack(trialPayload.toString());
            if (!Utilities.similar(base, trial)) {
                trial.addAttack(injector.probeAttack(trialPayload.toString()));
                trial.addAttack(injector.probeAttack(trialPayload.toString()));
                if (!Utilities.similar(base, trial)) {
                    bucketSize = bucketSize / 2;
                    break;
                }
            }
            if (bucketSize >= 65536 || (bucketSize >= 256 && type == IParameter.PARAM_JSON)) {
                break;
            }

            bucketSize = bucketSize * 2;
        }
        recentParams = new CircularFifoQueue<>(bucketSize *3);
        Utilities.out("Selected bucket size: "+ bucketSize + " for "+ targetURL);

        if(baseRequestResponse.getRequest()[0] != 'G') {
            invertedBase = Utilities.helpers.toggleRequestMethod(baseRequestResponse.getRequest());
            altBase = new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase));
            if(Utilities.helpers.analyzeResponse(altBase.getFirstRequest().getResponse()).getStatusCode() != 404) {
                altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));
                altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));
                altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));
                tryMethodFlip = true;
            }
        }

        // put the params into buckets
        paramBuckets = new ArrayDeque<>();
        ParamGuesser.addParams(paramBuckets, valueParams, bucketSize, false);
        ParamGuesser.addParams(paramBuckets, params, bucketSize, false);

        alreadyReported = ParamGuesser.getBlacklist(type);

        //Utilities.log("Trying " + (valueParams.size()+ params.size()) + " params in ~"+ paramBuckets.size() + " requests. Going from "+start + " to "+stop);

        bonusParams = new WordProvider();
        bonusParams.addSource("/Users/james/Dropbox/lists/favourites/disc_words-caseless.txt");
        bonusParams.addSource("/usr/share/dict/words");
    }

    Attack updateBaseline() {
        this.base = this.injector.probeAttack(Utilities.randomString(6));
        for(int i=0; i<4; i++) {
            base.addAttack(this.injector.probeAttack(Utilities.randomString((i+1)*(i+1))));
        }
        base.addAttack(this.injector.probeAttack(Utilities.randomString(6)+"|"+Utilities.randomString(12)));
        return base;
    }


    private static ParamInsertionPoint getInsertionPoint(IHttpRequestResponse baseRequestResponse, byte type, String payload, String attackID) {
        return type == IParameter.PARAM_JSON ?
                new JsonParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID) :
                new ParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID);
    }
}
