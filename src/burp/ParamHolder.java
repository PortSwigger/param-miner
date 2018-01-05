package burp;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;

class ParamHolder {
    Deque<ArrayList<String>> paramBuckets;
    byte type;
    int bucketSize;

    ParamHolder(byte type, int bucketSize) {
        this.type = type;
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
        params.remove("");

        if (type == Utilities.PARAM_HEADER) {
            params.removeIf(x -> Character.isDigit(x.charAt(0)));
            params.replaceAll(String::toLowerCase);
        }
    }
}
