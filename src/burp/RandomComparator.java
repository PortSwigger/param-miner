package burp;

import java.util.Comparator;

class RandomComparator implements Comparator<Object> {
    @Override
    public int compare(Object o1, Object o2) {
        int h1 = o1.hashCode();
        int h2 = o2.hashCode();
        if (h1 < h2) {
            return -1;
        }
        else  if (h1 == h2) {
            return 0;
        }
        return 1;
    }
}
