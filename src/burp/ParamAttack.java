package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.collections4.queue.CircularFifoQueue;

import java.util.*;

import static java.lang.Math.min;

class ParamAttack {

    CircularFifoQueue<String> recentParams;
    HashSet<String> alreadyReported;
    ArrayList<String> params;
    ArrayList<String> valueParams;
    int seed = -1;
    boolean started;

    private WordProvider bonusParams;
    private HashMap<String, String> requestParams;
    private ParamHolder paramBuckets;
    private int bucketSize = 1;
    private IHttpRequestResponse baseRequestResponse;
    private PayloadInjector injector;
    private String attackID;
    private Attack base;
    private String targetURL;
    private Attack altBase;

    final byte type;
    private ConfigurableSettings config;
    private ArrayList<String> headerMutations;

    int getStop() {
        return stop;
    }

    void incrStop() {
        stop += config.getInt("rotation increment");
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

    Attack getBase() {
        return base;
    }

    String getAttackID() {
        return attackID;
    }

    PayloadInjector getInjector() {
        return injector;
    }

    ParamHolder getParamBuckets() {
        return paramBuckets;
    }

    int getBucketSize() {
        return bucketSize;
    }

    IHttpRequestResponse getBaseRequestResponse() {
        return baseRequestResponse;
    }

    ArrayList<String> getHeaderMutations() { return headerMutations; }

    void setHeaderMutations(ArrayList<String> mutations) { this.headerMutations = mutations; }


    ParamAttack(IHttpRequestResponse baseRequestResponse, byte type, ParamGrabber paramGrabber, int stop, ConfigurableSettings config) {
        started = false;
        this.type = type;
        this.stop = stop;
        this.config = config;
        this.baseRequestResponse = baseRequestResponse;
        targetURL = baseRequestResponse.getHttpService().getHost();
        params = calculatePayloads(baseRequestResponse, paramGrabber, type);
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
        attackID = BulkUtilities.mangle(Arrays.hashCode(baseRequestResponse.getRequest())+"|"+System.currentTimeMillis()).substring(0,2);

        requestParams = new HashMap<>();
        for (String entry: Keysmith.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>())) {
            String[] parsed = Keysmith.parseKey(entry);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }

        final String payload = ""; // formerly "<a`'\\\"${{\\\\"


        // todo create collab context here and pass in?
        ParamInsertionPoint insertionPoint = getInsertionPoint(baseRequestResponse, type, payload, attackID);

        injector = new PayloadInjector(baseRequestResponse, insertionPoint);

        updateBaseline();

        //String ref = BulkUtilities.getHeader(baseRequestResponse.getRequest(), "Referer");
        //HashMap<String, Attack> baselines = new HashMap<>();
        //baselines.put(ref, new Attack(baseRequestResponse));

        int longest = config.getInt("max param length");

        // fixme this may exceed the max bucket size
        calculateBucketSize(type, longest);

        if (!BulkUtilities.globalSettings.getBoolean("carpet bomb")) {
            StringBuilder basePayload = new StringBuilder();
            for (int i = 1; i < min(8, bucketSize); i++) {
                basePayload.append("|");
                basePayload.append(BulkUtilities.randomString(longest));
                if (i % 4 == 0) {
                    base.addAttack(injector.probeAttack(basePayload.toString()));
                }
            }
        }

        // calculateBucketSize(type, longest); was here

        recentParams = new CircularFifoQueue<>(bucketSize *3);
        BulkUtilities.log("Selected bucket size: "+ bucketSize + " for "+ targetURL);

        // put the params into buckets
        paramBuckets = new ParamHolder(type, bucketSize);
        paramBuckets.addParams(valueParams, false);
        paramBuckets.addParams(params, false);

        if (!config.getBoolean("dynamic keyload")) {
            params = null;
            valueParams = null;
        }

        alreadyReported = getBlacklist(type);
        //BulkUtilities.log("Trying " + (valueParams.size()+ params.size()) + " params in ~"+ paramBuckets.size() + " requests. Going from "+start + " to "+stop);
    }

    private void calculateBucketSize(byte type, int longest) {
        if (config.getInt("force bucketsize") != -1) {
            bucketSize = config.getInt("force bucketsize");
            return;
        }

        switch(type) {
            case IParameter.PARAM_BODY:
                bucketSize = 128;
                break;
            case BulkUtilities.PARAM_HEADER:
                bucketSize = 8;
            case IParameter.PARAM_URL:
                bucketSize = 16;
                break;
            default:
                bucketSize = 32;
        }

        while (true) {
            BulkUtilities.log("Trying bucket size: "+ bucketSize);
            long start = System.currentTimeMillis();
            StringBuilder trialPayload = new StringBuilder();
            trialPayload.append(BulkUtilities.randomString(longest));
            for (int i = 0; i < bucketSize; i++) {
                trialPayload.append("|");
                trialPayload.append(BulkUtilities.randomString(longest));
            }

            Attack trial = injector.probeAttack(trialPayload.toString());
            if (!BulkUtilities.similar(base, trial)) {
                trial.addAttack(injector.probeAttack(trialPayload.toString()));
                trial.addAttack(injector.probeAttack(trialPayload.toString()));
                if (!BulkUtilities.similar(base, trial)) {
                    bucketSize = bucketSize / 2;
                    break;
                }
            }

            long end = System.currentTimeMillis();
            if (end - start > 5000) {
                bucketSize = bucketSize / 2;
                BulkUtilities.out("Setting bucketSize to "+bucketSize+" due to slow response");
                break;
            }

            if (bucketSize >= BulkUtilities.globalSettings.getInt("max bucketsize")) {
                break;
            }

            bucketSize = bucketSize * 2;
        }
    }

    private HashSet<String> getBlacklist(byte type) {
        HashSet<String> blacklist = new HashSet<>();
        switch(type) {
            case IParameter.PARAM_COOKIE:
                blacklist.add("__cfduid");
                blacklist.add("PHPSESSID");
                blacklist.add("csrftoken");
                blacklist.addAll(Keysmith.getParamKeys(baseRequestResponse.getRequest(), new HashSet<>(IParameter.PARAM_COOKIE)));
                break;
            case IParameter.PARAM_URL:
                blacklist.add("lang");
                blacklist.addAll(Keysmith.getParamKeys(baseRequestResponse.getRequest(), new HashSet<>(IParameter.PARAM_URL, IParameter.PARAM_BODY)));
                break;
            case IParameter.PARAM_BODY:
                blacklist.addAll(Keysmith.getParamKeys(baseRequestResponse.getRequest(), new HashSet<>(IParameter.PARAM_URL, IParameter.PARAM_BODY)));
                break;
            case BulkUtilities.PARAM_HEADER:
                if (BulkUtilities.globalSettings.getBoolean("skip boring words")) {
                    blacklist.addAll(BulkUtilities.boringHeaders);
                }
                break;
            default:
                BulkUtilities.out("Unrecognised type: "+type);
                break;
        }

        if (BulkUtilities.globalSettings.getBoolean("only report unique params")) {
            blacklist.addAll(BulkUtilities.reportedParams);
        }

        return blacklist;
    }

    Attack updateBaseline() {
        this.base = this.injector.probeAttack(BulkUtilities.randomString(6));
        int baselineSize = BulkUtilities.globalSettings.getInt("baseline size");
        for(int i=0; i<baselineSize; i++) {
            base.addAttack(this.injector.probeAttack(BulkUtilities.randomString((i+1)*(i+1))));
        }
        if (bucketSize > 1) {
            base.addAttack(this.injector.probeAttack(BulkUtilities.randomString(6) + "|" + BulkUtilities.randomString(12)));
        }
        return base;
    }


    private static ParamInsertionPoint getInsertionPoint(IHttpRequestResponse baseRequestResponse, byte type, String payload, String attackID) {
        switch(type) {
            case IParameter.PARAM_JSON:
                return new JsonParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID);
            case BulkUtilities.PARAM_HEADER:
                return new HeaderNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID);
            default:
                return new ParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID);
        }
    }

    ArrayList<String> calculatePayloads(IHttpRequestResponse baseRequestResponse, ParamGrabber paramGrabber, byte type) {
        ArrayList<String> params = new ArrayList<>();

        // collect keys in request, for key skipping, matching and re-mapping
        HashMap<String, String> requestParams = new HashMap<>();
        for (String entry: Keysmith.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>())) { // todo give precedence to shallower keys
            String[] parsed = Keysmith.parseKey(entry);
            BulkUtilities.log("Request param: " +parsed[1]);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }

        // add JSON from response
        params.addAll(Keysmith.getAllKeys(baseRequestResponse.getResponse(), requestParams));

        // add JSON from method-flip response
        if(baseRequestResponse.getRequest()[0] != 'G') {
            IHttpRequestResponse getreq = Scan.request(baseRequestResponse.getHttpService(),
                    BulkUtilities.helpers.toggleRequestMethod(baseRequestResponse.getRequest()));
            params.addAll(Keysmith.getAllKeys(getreq.getResponse(), requestParams));
        }


        // add JSON from elsewhere
        HashMap<Integer, Set<String>> responses = new HashMap<>();

        Iterator<IHttpRequestResponse> savedJson = paramGrabber.getSavedJson().iterator();
        while (savedJson.hasNext()) {
            IHttpRequestResponse resp = null; // todo record resp
            try {
                resp = savedJson.next();
            }
            catch (NoSuchElementException e) {
                break;
            }

            JsonParser parser = new JsonParser();
            JsonElement json = parser.parse(BulkUtilities.getBody(resp.getResponse()));
            HashSet<String> keys = new HashSet<>(Keysmith.getJsonKeys(json, requestParams));
            int matches = 0;
            for (String requestKey: keys) {
                if (requestParams.containsKey(requestKey) || requestParams.containsKey(Keysmith.parseKey(requestKey)[1])) {
                    matches++;
                }
            }

            // if there are no matches, don't bother with prefixes
            // todo use root (or non-leaf) objects only
            if(matches < 1) {
                //BulkUtilities.out("No matches, discarding prefix");
                HashSet<String> filteredKeys = new HashSet<>();
                for(String key: keys) {
                    String lastKey = Keysmith.parseKey(key)[1];
                    if (BulkUtilities.parseArrayIndex(lastKey) < 3) {
                        filteredKeys.add(Keysmith.parseKey(key)[1]);
                    }
                }
                keys = filteredKeys;
            }

            Integer matchKey = matches;
            if(responses.containsKey(matchKey)) {
                responses.get(matchKey).addAll(keys);
            }
            else {
                responses.put(matchKey, keys);
            }
        }

        final TreeSet<Integer> sorted = new TreeSet<>(Collections.reverseOrder());
        sorted.addAll(responses.keySet());
        for(Integer key: sorted) {
            BulkUtilities.log("Loading keys with "+key+" matches");
            ArrayList<String> sortedByLength = new ArrayList<>(responses.get(key));
            sortedByLength.sort(new LengthCompare());
            params.addAll(sortedByLength);
        }

        if (params.size() > 0) {
            BulkUtilities.log("Loaded " + new HashSet<>(params).size() + " params from response");
        }

        bonusParams = new WordProvider();

        if (config.getBoolean("use custom wordlist")) {
            bonusParams.addSourceFile(config.getString("custom wordlist path"));
        }

        if (config.getBoolean("use assetnote params")) {
            bonusParams.addSourceFile("/assetnote-params");
        }


        if (type == BulkUtilities.PARAM_HEADER && config.getBoolean("use basic wordlist")) {
            bonusParams.addSourceFile("/headers");
        }

        if (config.getBoolean("request") || config.getBoolean("response-headers") || config.getBoolean("response-body") ) {

            if (config.getBoolean("response-headers")) {
                params.addAll(Keysmith.getWords(Utilities.getHeaders(baseRequestResponse.getResponse())));
            }

            if (config.getBoolean("response-body")) {
                params.addAll(Keysmith.getWords(Utilities.getBody(baseRequestResponse.getResponse())));
            }

            if (config.getBoolean("request")) {
                params.addAll(Keysmith.getWords(BulkUtilities.helpers.bytesToString(baseRequestResponse.getRequest())));
            }

            params.addAll(paramGrabber.getSavedGET());
            params.addAll(paramGrabber.getSavedWords());

            if (type == BulkUtilities.PARAM_HEADER) {
                params.replaceAll(x -> x.toLowerCase().replaceAll("[^a-z0-9_-]", ""));
                params.replaceAll(x -> x.replaceFirst("^[_-]+", ""));
                params.remove("");
            }

            // de-dupe without losing the ordering
            params = new ArrayList<>(new LinkedHashSet<>(params));

            params.replaceAll(x -> x.substring(0, min(x.length(), config.getInt("max param length"))));

            bonusParams.addSourceWords(String.join("\n", params));
        }

        if (type != BulkUtilities.PARAM_HEADER && config.getBoolean("use basic wordlist")) {
            bonusParams.addSourceFile("/params");
        }

        if (config.getBoolean("use bonus wordlist")) {
            bonusParams.addSourceFile("/functions");
            if (type != BulkUtilities.PARAM_HEADER) {
                bonusParams.addSourceFile("/headers");
            }
            else {
                bonusParams.addSourceFile("/params");
            }
            bonusParams.addSourceFile("/words");
        }

        // only use keys if the request isn't JSON
        // todo accept two levels of keys if it's using []
        //if (type != IParameter.PARAM_JSON) {
        //    for(int i=0;i<params.size();i++) {
        //        params.set(i, Keysmith.parseKey(params.get(i))[1]);
        //    }
        //}



        return new ArrayList<>();
    }
}
