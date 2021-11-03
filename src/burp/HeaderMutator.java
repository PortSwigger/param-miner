package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

public class HeaderMutator {
    public ArrayList<String> mutations;

    HeaderMutator() {
        this.mutations = new ArrayList<String>();

        this.registerMutation("nospace");
        this.registerMutation("underscore");
        this.registerMutation("cr-hyphen");
        this.registerMutation("letter-hyphen");

        this.registerMutation("linePrefixSpace");
        this.registerMutation("linePrefixTab");
        this.registerMutation("linePrefixVTab");
        this.registerMutation("linePrefixNull");

        this.registerMutation("lineAppendixNull");

        this.registerMutation("colonPreNull");
        this.registerMutation("colonPreSpace");
        this.registerMutation("colonPreTab");
        this.registerMutation("colonPreVTab");
        this.registerMutation("colonPreCR");
        this.registerMutation("colonPreLF");
        this.registerMutation("colonPreJunk");

        this.registerMutation("colonPostNull");
        this.registerMutation("colonPostSpace");
        this.registerMutation("colonPostTab");
        this.registerMutation("colonPostVTab");
        this.registerMutation("colonPostCR");
        this.registerMutation("colonPostLF");
        this.registerMutation("colonPostJunk");

        this.registerMutation("singleQuote");
        this.registerMutation("doubleQuote");

        this.registerMutation("upperCase");
        this.registerMutation("lowerCase");
        this.registerMutation("mixedCase");

        this.registerMutation("headerStartLF");
        this.registerMutation("headerStartDoubleLF");
        this.registerMutation("headerStartCR");
        this.registerMutation("headerStartDoubleCR");
        this.registerMutation("headerEndLF");
        this.registerMutation("headerEndDoubleLF");
        this.registerMutation("headerEndCR");
        this.registerMutation("headerEndDoubleCR");
    }

    private void registerMutation(String name) {
        this.mutations.add(name);
    }

    public byte[] mutate(String header, String mutation) {
        String retStr = null;
        byte[] ret = null;
        switch (mutation) {
            case "nospace":
                retStr = header.replaceFirst(": ", ":");
                break;

            case "underscore":
                retStr = header.replaceFirst("-", "_");
                break;

            case "cr-hyphen":
                retStr = header.replaceFirst("-", "\r");
                break;

            case "letter-hyphen":
                retStr = header.replaceFirst("-", "s");
                break;

            case "linePrefixSpace":
                retStr = " " + header;
                break;

            case "linePrefixTab":
                retStr = "\t" + header;
                break;

            case "linePrefixVTab":
                retStr = new String(new byte[]{(byte)0x0b}) + header;
                break;

            case "linePrefixNull":
                retStr = new String(new byte[]{(byte)0x00}) + header;
                break;

            case "lineAppendixNull":
                retStr = header + new String(new byte[]{(byte)0x00});
                break;

            case "colonPreNull":
                retStr = header.replaceFirst(":", "\0:");
                break;

            case "colonPreSpace":
                retStr = header.replaceFirst(":", " :");
                break;

            case "colonPreTab":
                retStr = header.replaceFirst(":", "\t:");
                break;

            case "colonPreVTab":
                retStr = header.replaceFirst(":", new String(new byte[]{0x0b}) + ":");
                break;

            case "colonPreCR":
                retStr = header.replaceFirst(":", "\r:");
                break;

            case "colonPreLF":
                retStr = header.replaceFirst(":", "\n:");
                break;

            case "colonPreJunk":
                retStr = header.replaceFirst(":", " abcd:");
                break;

            case "colonPostNull":
                retStr = header.replaceFirst(":", ":\0");
                break;

            case "colonPostSpace":
                retStr = header.replaceFirst(":", ": ");
                break;

            case "colonPostTab":
                retStr = header.replaceFirst(":", ":\t");
                break;

            case "colonPostVTab":
                retStr = header.replaceFirst(":", ":" + new String(new byte[]{0x0b}));
                break;

            case "colonPostCR":
                retStr = header.replaceFirst(":", ":\r");
                break;

            case "colonPostLF":
                retStr = header.replaceFirst(":", ":\n");
                break;

            case "colonPostJunk":
                retStr = header.replaceFirst(":", ":abcd ");
                break;

            case "singleQuote":
                retStr = header.replaceFirst(":\\s*", ": '").replaceFirst("$", "'");
                break;

            case "doubleQuote":
                retStr = header.replaceFirst(":\\s*", ": \"").replaceFirst("$", "\"");
                break;

            case "upperCase":
                retStr = header.toUpperCase();
                break;

            case "lowerCase":
                retStr = header.toLowerCase();
                break;

            case "mixedCase":
                retStr = "";
                for (int i = 0; i < header.length(); i++) {
                    char c;
                    if (i%2 == 0) {
                        c = Character.toLowerCase(header.charAt(i));
                    } else {
                        c = Character.toUpperCase(header.charAt(i));
                    }
                    retStr = retStr + c;
                }
                break;

            case "headerStartLF":
                retStr = "Foo: Bar\n" + header;
                break;

            case "headerStartDoubleLF":
                retStr = "Foo: Bar\n\n" + header;
                break;

            case "headerStartCR":
                retStr = "Foo: Bar\r" + header;
                break;

            case "headerStartDoubleCR":
                retStr = "Foo: Bar\r\r" + header;
                break;

            case "headerEndLF":
                retStr = header + "\nFoo: Bar";
                break;

            case "headerEndDoubleLF":
                retStr = header + "\n\nFoo: Bar";
                break;

            case "headerEndCR":
                retStr = header + "\rFoo: Bar";
                break;

            case "headerEndDoubleCR":
                retStr = header + "\r\rFoo: Bar";
                break;

            default:
                Utilities.out("Unknown mutation " + mutation + " requested!");
                retStr = header;
                break;
        }

        if (ret == null && retStr != null) {
            return retStr.getBytes(StandardCharsets.UTF_8);
        }
        return ret;
    }

    public byte[] mutateRequest(byte[] req, String mutation, String[] headers) throws IOException {
        ByteArrayOutputStream ret = new ByteArrayOutputStream();

        // Get sorted header offsets, and a sorted array of their indices, sorted by the start offset of the header
        ArrayList<int[]> offsets = new ArrayList<int[]>();
        for (int i = 0; i < headers.length; i++) {
            String header = headers[i];
            if (header.contains("~")) {
                header = header.split("~", 2)[0];
            }
            int[] offs = Utilities.getHeaderOffsets(req, header);
            if (offs !=  null) {
                offsets.add(offs);
            }
        }

        offsets.sort(new java.util.Comparator<int[]>(){
            public int compare(int[] a, int[] b) {
                return Integer.compare(a[0], b[0]);
            }
        });
        // Copy over req to ret, replacing headers as we go
        int offset = 0;
        Iterator<int[]> iterator = offsets.iterator();
        while (iterator.hasNext()) {
            int[] markers = iterator.next();
            int headerStart = markers[0];
            int headerEnd = markers[2];

            // Copy up to the start of the header

            // Duplicate headers cause an issue here. However, switching offset and headerStart seems to just fix it.
            if (offset >= headerStart) {
                int tmp = offset;
                offset = headerStart;
                headerStart = tmp;
            }
            ret.write(Arrays.copyOfRange(req, offset, headerStart));
            offset = headerEnd;

            // Copy in mutated header
            byte[] headerBytes = Arrays.copyOfRange(req, headerStart, headerEnd);
            String headerStr = new String(headerBytes, StandardCharsets.UTF_8);
            byte[] newHeader = this.mutate(headerStr, mutation);
            ret.write(newHeader);
        }

        // Copy in rest of request
        ret.write(Arrays.copyOfRange(req, offset, req.length));

        return ret.toByteArray();
    }
}
