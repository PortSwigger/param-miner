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

    String toHyphenatedPascalCaseIgnorePercent(String s) {
        StringBuilder b = new StringBuilder(s.length());

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            // Do not capitalize the character after a percentage sign. This is used for string interpolation by the extension to add IP and Port information to HTTP headers
            if (i == 0 || (!Character.isLetterOrDigit(s.charAt(i-1)) && s.charAt(i-1) != '%')) {
                b.append(Character.toUpperCase(c));   
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    void addParams(ArrayList<String> params, boolean topup) {
        removeBadEntries(params);

        if(type == BulkUtilities.PARAM_HEADER) {
            int max = params.size();
            for (int i=0; i<max; i++) {
                String param = params.get(i);
                if (param.contains("-") && BulkUtilities.globalSettings.getBoolean("try -_ bypass")) {
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

            if (BulkUtilities.globalSettings.getBoolean("include Hyphenated-Pascal-Case headers")) {
                max = params.size();
                params.ensureCapacity(max*2);
                for (int i=0; i<max; i++) {
                    String param = params.get(i);
                    String pascalCaseParam = toHyphenatedPascalCaseIgnorePercent(param);
                    if (!pascalCaseParam.equals(param)) {
                        params.add(pascalCaseParam);
                    }
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

        if (type == BulkUtilities.PARAM_HEADER) {
            params.removeIf(x -> Character.isDigit(x.charAt(0)));
            if (BulkUtilities.globalSettings.getBoolean("lowercase headers")) {
                params.replaceAll(String::toLowerCase);
            }
        }
    }
}
