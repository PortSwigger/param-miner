package burp;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayDeque;
import java.util.Scanner;

class WordProvider {

    private Scanner currentSource;
    private ArrayDeque<String> fileSources = new ArrayDeque<>();
    private ArrayDeque<String> sourceWords = new ArrayDeque<>();

    void addSourceFile(String filename) {
        fileSources.add(filename);
    }

    void addSourceWords(String wordlist) {
        sourceWords.add(wordlist);
    }

    String getNext() {
        getNextSource();
        if (currentSource == null || !currentSource.hasNextLine()){
            return null;
        }
        return currentSource.nextLine();
    }

    private void getNextSource() {
        if (currentSource != null && currentSource.hasNextLine()) {
            return;
        }

        while (!fileSources.isEmpty()) {
            String filename = fileSources.removeFirst();
            try {
                currentSource = new Scanner(getClass().getResourceAsStream(filename));
                if (currentSource.hasNextLine()) {
                    return;
                }
            } catch (NullPointerException e) {
                try {
                    currentSource = new Scanner(new File(filename));
                    if (currentSource.hasNextLine()) {
                        return;
                    }
                }
                catch (FileNotFoundException f) {
                    Utilities.out("Wordlist not foundL "+filename);
                }
            }
        }

        if (!sourceWords.isEmpty()) {
            String words = sourceWords.removeFirst();
            currentSource = new Scanner(words);
            return;
        }

        currentSource = null;
    }

}
