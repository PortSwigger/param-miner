package burp;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class InputTransformationParamScan extends ParamScan {

    InputTransformationParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IHttpService service = baseRequestResponse.getHttpService();

        // set value to canary
        String canary = BulkUtilities.toCanary(BulkUtilities.generateCanary());
        String cacheBuster = BulkUtilities.generateCanary();


        byte[] poison = insertionPoint.buildRequest(canary.getBytes());

        byte[] confirmation = BulkUtilities.addCacheBuster(poison, cacheBuster);

        // confirm we have input reflection
        Resp resp = request(service, confirmation);
        if (!BulkUtilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            return null;
        }

        // Normalisation
        List<NormalisationEncoder> encoders = new ArrayList<>();

        encoders.add(new OverlongUnicodeEncoder("Overlong-encoded parameter"));
        encoders.add(new UnicodeOverflowEncoder("Unicode-overflow parameter"));
        encoders.add(new CircledAlphaDigitEncoder("Unicode-normalised parameter"));

        List<ParsedHttpParameter> parameters = BulkUtilities.buildMontoyaReq(poison,baseRequestResponse.getHttpService()).parameters();
        Optional<ParsedHttpParameter> parameter = parameters.stream().filter(iParameter -> iParameter.value().equalsIgnoreCase(canary) && iParameter.type() == HttpParameterType.COOKIE).findFirst();
        if (parameter.isPresent()) {
            encoders.add(new QuotedOctalEncoder("Quoted octal-encoded cookie parameter"));
            encoders.add(new QuotedStringEncoder("Quoted legacy cookie parameter"));
        }

        for (NormalisationEncoder encoder: encoders) {
            try {
                String prob = BulkUtilities.toCanary(BulkUtilities.generateCanary());
                List<byte[]> variations =  encoder.encode(prob);
                for (byte[] variant : variations) {

                    byte[] victim = BulkUtilities.replaceFirst(poison, canary.getBytes(), variant);
                    if (parameter.isPresent() && encoder instanceof QuotedStringEncoder) {
                        victim = BulkUtilities.replaceFirst(victim, parameter.get().name().getBytes(), String.format("$Version=1;%s",parameter.get().name()).getBytes());
                    }
                    victim = BulkUtilities.addCacheBuster(victim, BulkUtilities.generateCanary());
                    Resp poisoned = request(service, victim);
                    if (!BulkUtilities.containsBytes(poisoned.getReq().getResponse(), prob.getBytes())) {
                        continue;
                    }

                    report(encoder.getName(), "This was confirmed using the " + prob + ".", resp, poisoned);
                }
            }catch (Exception ignored) {}
        }
        return null;
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }
}
class NormalisationEncoder {
    String name = "";

    NormalisationEncoder(String name) {
        this.name = name;
    }

    public static byte[] escape(byte[] str) {
        StringBuilder sb = new StringBuilder();
        for (byte c : str) {
            sb.append(String.format("%%%02X", c));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    public String getName() {
        return name;
    }

    public List<byte[]> encode(String prob) throws Exception{
        return new ArrayList<>();
    }
}
class CircledAlphaDigitEncoder extends NormalisationEncoder {
    public CircledAlphaDigitEncoder(String name) {
        super(name);
    }
    public static byte[] circledAlphaDigit(String input) {
        final int baseUpper = 0x24B6; // Starting point for 'Ⓐ' (A)
        final int baseLower = 0x24D0; // Starting point for 'ⓐ' (a)
        final int baseDigit = 0x2460; // Starting point for '①' (1)

        Map<Character, Character> alphaMap = new HashMap<>();

        for (int i = 0; i < 26; i++) {
            alphaMap.put((char) (65 + i), (char) (baseUpper + i));
        }

        for (int i = 0; i < 26; i++) {
            alphaMap.put((char) (97 + i), (char) (baseLower + i));
        }

        for (int i = 0; i < 9; i++) {
            alphaMap.put((char) (49 + i), (char) (baseDigit + i));
        }

        alphaMap.put('0', '\u24EA'); // Circled number 0

        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            // Check if there is a mapped circled version of the character
            if (alphaMap.containsKey(c)) {
                sb.append(alphaMap.get(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    public List<byte[]> encode(String input) throws Exception {
        return List.of(
                circledAlphaDigit(input),
                escape(circledAlphaDigit(input)));
    }
}
class UnicodeOverflowEncoder extends NormalisationEncoder {

    public UnicodeOverflowEncoder(String name) {super(name);}

    public static byte[] convertOverlongUTF8(String code) {
        char[] arr = code.toCharArray();
        byte[] result = new byte[arr.length * 4];
        for (int i = 0; i < arr.length ; i++) {
            byte[] e = overlongUTF8ByteSequence(arr[i]);
            System.arraycopy(e, 0, result, i*4, 4);
        }
        return result;
    }

    private static byte[] overlongUTF8ByteSequence(char c) {
        byte[] baseSequence = {(byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80};
        baseSequence[3] += (byte) c;
        return baseSequence;
    }

    public List<byte[]> encode(String input) throws Exception {
        return List.of(
                convertOverlongUTF8(input),
                escape(convertOverlongUTF8(input)));
    }
}
class  QuotedStringEncoder extends NormalisationEncoder {
    public QuotedStringEncoder(String name) { super(name); }

    public static String convertToQuotedString(String value) {
        StringBuilder quotedValue = new StringBuilder("\"");

        for (char c : value.toCharArray()) {
            quotedValue.append("\\").append(c);
        }

        quotedValue.append("\"");
        return quotedValue.toString();
    }

    public List<byte[]> encode(String input) throws Exception {
        return List.of(convertToQuotedString(input).getBytes(StandardCharsets.UTF_8));
    }
}

class QuotedOctalEncoder extends NormalisationEncoder {
    public QuotedOctalEncoder(String name) { super(name); }

    public static String convertToQuotedCookie(String value) {
        StringBuilder quotedValue = new StringBuilder("\"");

        for (char c : value.toCharArray()) {
            quotedValue.append("\\").append(String.format("%03o", (int) c));
        }

        quotedValue.append("\"");
        return quotedValue.toString();
    }

    public List<byte[]> encode(String input) throws Exception {
        return List.of(convertToQuotedCookie(input).getBytes(StandardCharsets.UTF_8));
    }
}

class OverlongUnicodeEncoder extends NormalisationEncoder {

    OverlongUnicodeEncoder(String name) { super(name); }

    public static byte[] overLongUTF8(int chr, int n) {

        List<Character> chars = new ArrayList<>();
        chars.add((char) ((0x100 - (1 << (8 - n))) | ((1 << (7 - n)) - 1 & (chr >> (6 * (n - 1))))));
        chr %= n < 7 ? 1 << 6 * (n - 1) : (int) Math.pow(2, 6 * (n - 1));

        for (int i = 1; i < n; i++) {
            chars.add((char) (0x80 | (63 & (chr >> 6 * (n - i - 1)))));
            chr %= n < 7 ? 1 << 6 * (n - i - 1) : (int) Math.pow(2, 6 * (n - i - 1));
        }

        byte[] byteArray = new byte[chars.size()];

        for (int i = 0; i < chars.size(); i++) {
            char character = chars.get(i);
            byteArray[i] = (byte) character;
        }

        return byteArray;
    }
    public static byte[] convertOverlongUTF8(String code, int length) {
        char[] arr = code.toCharArray();
        byte[] result = new byte[arr.length * length];
        for (int i = 0; i < arr.length ; i++) {
            byte[] e = overLongUTF8(arr[i], length);
            System.arraycopy(e, 0, result, i*length, length);
        }
        return result;
    }

    public List<byte[]> encode(String input) throws Exception {
        List<byte[]> results = new ArrayList<>();
        for(int i = 2; i < 5; i++) {
            byte[] payload = convertOverlongUTF8(input, i);
            results.add(payload);
            results.add(escape(payload));
        }
        return results;
    }
}