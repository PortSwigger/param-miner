package burp.model.utilities;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayDeque;
import java.util.Scanner;

public class WordProvider {

    private Scanner currentSource;
    private ArrayDeque<String> sources = new ArrayDeque<>();

    public void addSource(String source) {
        sources.add(source);
    }

    public String getNext() {
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

        while (!sources.isEmpty()) {
            String filename = sources.removeFirst();
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
                    if (filename.contains("\n")) {
                        currentSource = new Scanner(filename);
                        return;
                    }

                }
            }
        }

        currentSource = null;
    }

}
