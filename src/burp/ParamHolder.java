package burp;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;

class ParamHolder {
    private Deque<ArrayList<String>> paramBuckets;
    private byte type;
    private int bucketSize;

    ParamHolder(byte type, int bucketSize) {
        this.type = type;
        this.bucketSize = bucketSize;
        paramBuckets = new ArrayDeque<>();
    }

    int size() {
        return paramBuckets.size();
    }

    ArrayList<String> pop() {
        return paramBuckets.pop();
    }

    void push(ArrayList<String> e) {
        paramBuckets.push(e);
    }

    void addParams(ArrayList<String> params, boolean topup) {
        removeBadEntries(params);

        if(type == Utilities.PARAM_HEADER) {
            int max = params.size();
            for (int i=0; i<max; i++) {
                String param = params.get(i);
                if (param.contains("-") && Utilities.globalSettings.getBoolean("try -_ bypass")) {
                    params.add(param.replace("-", "_"));
                }
            }
            max = params.size();
            params.ensureCapacity(max*2);
            for (int i=0; i<max; i++) {
                String param = params.get(i);
                if (param.startsWith("x-") || param.startsWith("x_")) {
                    params.add(param.substring(2));
                }
                else {
                    params.add("x-"+param);
                }
            }
        }

        int limit = params.size();
        if(limit == 0) {
            return;
        }

        if(topup && !paramBuckets.isEmpty()) {
            int i = 0;
            ArrayList<String> last = paramBuckets.getLast();
            while(last.size() < bucketSize && i < params.size()) {
                last.add(params.get(i++));
            }

            if (i == params.size()) {
                return;
            }
        }

        for (int i = 0; i<limit; i+= bucketSize) { // i<limit + bucketSize
            ArrayList<String> bucket = new ArrayList<>();
            for(int k = 0; k< bucketSize && i+k < limit; k++) {
                String param = params.get(i+k);
                bucket.add(param);
            }
            paramBuckets.add(bucket);
        }
    }

    private void removeBadEntries(ArrayList<String> params) {
        params.removeAll(Arrays.asList(""));

        if (type == Utilities.PARAM_HEADER) {
            params.removeIf(x -> Character.isDigit(x.charAt(0)));
            if (Utilities.globalSettings.getBoolean("lowercase headers")) {
                params.replaceAll(String::toLowerCase);
            }
        }
    }
}
