package burp;

import org.graalvm.compiler.core.common.util.Util;
import sun.awt.WindowIDProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;

public class HeaderMutator {
    public ArrayList<String> mutations;

    HeaderMutator() {
        this.mutations = new ArrayList<String>();

        this.registerMutation("nospace");
        this.registerMutation("namejunk");
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

            case "namejunk":
                retStr = header.replaceFirst(":", " abcd:");
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
