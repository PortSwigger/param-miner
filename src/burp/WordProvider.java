package burp;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayDeque;
import java.util.Scanner;

class WordProvider {

    private Scanner currentSource;
    private ArrayDeque<String> sources = new ArrayDeque<>();

    void addSource(String source) {
        sources.add(source);
    }

    String getNext() {
        getNextSource();
        if (currentSource == null || !currentSource.hasNext()){
            return null;
        }
        return currentSource.next();
    }

    private void getNextSource() {
        if (currentSource != null && currentSource.hasNext()) {
            return;
        }

        while (!sources.isEmpty()) {
            try {
                currentSource = new Scanner(new File(sources.removeFirst()));
                if (currentSource.hasNext()) {
                    return;
                }
            } catch (FileNotFoundException e) {
                ;
            }
        }

        currentSource = null;
    }

}
