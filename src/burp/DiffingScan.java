package burp;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;


class DiffingScan {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    DiffingScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    private Attack buildAttack(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Probe probe, String payload) {
        boolean randomAnchor = probe.getRandomAnchor();
        byte prefix = probe.getPrefix();
        
        String anchor = "";
        if (randomAnchor) {
            anchor = Utilities.randomString(5) + Integer.toString(Utilities.rnd.nextInt(9));
        }

        String base_payload = payload;
        if (prefix == Probe.PREPEND) {
            payload += insertionPoint.getBaseValue();
        }
        else if (prefix == Probe.APPEND) {
            payload = insertionPoint.getBaseValue() + anchor + payload;
        }
        else if (prefix == Probe.REPLACE) {
            // payload = payload;
        }
        else {
            Utilities.err("Unknown payload position");
        }

        byte[] request = insertionPoint.buildRequest(payload.getBytes());
        IParameter cacheBuster = helpers.buildParameter(Utilities.randomString(8), "1", IParameter.PARAM_URL);
        request = helpers.addParameter(request, cacheBuster);

        IHttpRequestResponse req = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), request); // Utilities.buildRequest(baseRequestResponse, insertionPoint, payload)

        if(randomAnchor) {
            req = Utilities.highlightRequestResponse(req, anchor, anchor, insertionPoint);
        }

        Attack attack = new Attack(req, probe, base_payload, anchor);

        return attack;
    }

    private IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse) {
        IHttpRequestResponse[] requests = new IHttpRequestResponse[attacks.length];
        Probe bestProbe = null;
        String detail = "<br/><br/><b>Successful probes</b><br/><ul>";
        for (int i=0; i<attacks.length; i++) {
            requests[i] = attacks[i].req;
            if (i % 2 == 0) {
                detail += "<li><b>"+StringEscapeUtils.escapeHtml4(attacks[i].getProbe().getName())+"</b> &#x20; (<b style='color: red'>"+ StringEscapeUtils.escapeHtml4(attacks[i].payload)+ "</b> vs <b style='color: blue'> ";
            }
            else {
                detail += StringEscapeUtils.escapeHtml4(attacks[i].payload)+"</b>)</li>";
                detail += "<ul>";
                for (String mark : attacks[i].getPrint().keySet()) {
                    if (attacks[i-1].getPrint().containsKey(mark) && !attacks[i].getPrint().get(mark).equals(attacks[i-1].getPrint().get(mark))) {
                        detail += "<li>" + StringEscapeUtils.escapeHtml4(mark)+": "+"<b style='color: red'>"+StringEscapeUtils.escapeHtml4(attacks[i-1].getPrint().get(mark).toString()) + " </b>vs<b style='color: blue'> "+StringEscapeUtils.escapeHtml4(attacks[i].getPrint().get(mark).toString()) + "</b></li>";
                    }
                }

                detail += "</ul>";
            }
            if (bestProbe == null || attacks[i].getProbe().getSeverity() >= bestProbe.getSeverity()) {
                bestProbe = attacks[i].getProbe();
            }
        }

        detail += "</ul>";

        return new Fuzzable(requests, helpers.analyzeRequest(baseRequestResponse).getUrl(), bestProbe.getName(), detail); //attacks[attacks.length-2].getProbe().getName()
    }

    private boolean identical(Attack candidate, Attack attack2) {
        return candidate.getPrint().equals(attack2.getPrint());
    }


    private boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
        //if (!candidate.getPrint().keySet().equals(individualBreakAttack.getPrint().keySet())) {
        //    return false;
        //}
        for (String key: doNotBreakAttackGroup.getPrint().keySet()) {
            if (individualBreakAttack.getPrint().containsKey(key) && !individualBreakAttack.getPrint().get(key).equals(doNotBreakAttackGroup.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    private ArrayList<Attack> fuzz(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Attack basicAttack, Probe probe) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack breakAttack;
        Attack doNotBreakAttack;
        breakAttack = buildAttack(baseRequestResponse, insertionPoint, probe, probe.getNextBreak());

        if (identical(basicAttack, breakAttack)) {
            return new ArrayList<>();
        }

        for(int k=0; k<probe.getNextEscapeSet().length; k++) {
            doNotBreakAttack = buildAttack(baseRequestResponse, insertionPoint, probe, probe.getNextEscapeSet()[k]);
            doNotBreakAttack.addAttack(basicAttack);
            if(!similar(doNotBreakAttack, breakAttack)) {
                attacks = verify(baseRequestResponse, insertionPoint, doNotBreakAttack, probe, k);
                if (!attacks.isEmpty()) {
                    break;
                }
            }
        }

        return attacks;
    }

    private ArrayList<Attack> verify(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Attack doNotBreakAttack, Probe probe, int chosen_escape) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack breakAttack;

        for(int i=0; i<6; i++) {
            breakAttack = buildAttack(baseRequestResponse, insertionPoint, probe, probe.getNextBreak());
            if(similar(doNotBreakAttack, breakAttack)) {
                return new ArrayList<>();
            }

            doNotBreakAttack.addAttack(buildAttack(baseRequestResponse, insertionPoint, probe, probe.getNextEscapeSet()[chosen_escape]));
            if(similar(doNotBreakAttack, breakAttack)) {
                return new ArrayList<>();
            }
        }

        // this final probe pair is sent out of order, to prevent alternation false positives
        doNotBreakAttack.addAttack(buildAttack(baseRequestResponse, insertionPoint, probe, probe.getNextEscapeSet()[chosen_escape]));
        breakAttack = buildAttack(baseRequestResponse, insertionPoint, probe, probe.getNextBreak());

        if(similar(doNotBreakAttack, breakAttack)) {
            return new ArrayList<>();
        }

        attacks.add(breakAttack);
        attacks.add(doNotBreakAttack);

        return attacks;
    }

    private ArrayList<Attack> exploreAvailableFunctions(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Attack basicAttack, String prefix, String suffix, boolean useRandomAnchor) {
        ArrayList<Attack> attacks = new ArrayList<>();
        ArrayList<String[]> functions = new ArrayList<>();

        if (useRandomAnchor) {
            functions.add(new String[]{"Ruby injection", "1.to_s", "1.to_z", "1.tz_s"});
            functions.add(new String[]{"Python injection", "unichr(49)", "unichrr(49)", "unichn(97)"});
        }
        else {
            functions.add(new String[]{"Ruby injection", "1.abs", "1.abz", "1.abf"});
        }

        functions.add(new String[]{"JavaScript injection", "isFinite(1)", "isFinitez(1)", "isFinitee(1)"});
        functions.add(new String[]{"Shell injection", "$((1/1))", "$((1/0))", "$((2/0))"});
        functions.add(new String[]{"Basic function injection", "abs(1)", "abz(1)", "abf(1)"});

        if (!useRandomAnchor) {
            functions.add(new String[]{"Python injection", "int(unichr(49))", "int(unichrr(49))", "int(unichz(49))"});
        }


        functions.add(new String[]{"MySQL injection", "power(unix_timestamp(),0)", "power(unix_timestampp(),0)", "power(unix_timestanp(),0)"});
        functions.add(new String[]{"Oracle SQL injection", "to_number(1)", "to_numberr(1)", "to_numbez(1)"});
        functions.add(new String[]{"SQL Server injection", "power(current_request_id(),0)", "power(current_request_ids(),0)", "power(current_request_ic(),0)"});
        functions.add(new String[]{"PostgreSQL injection", "power(inet_server_port(),0)", "power(inet_server_por(),0)", "power(inet_server_pont(),0)"});
        functions.add(new String[]{"SQLite injection", "min(sqlite_version(),1)", "min(sqlite_versionn(),1)", "min(sqlite_versipn(),1)"});
        functions.add(new String[]{"PHP injection", "pow(phpversion(),0)", "pow(phpversionn(),0)", "pow(phpversiom(),0)"});
        functions.add(new String[]{"Perl injection", "(getppid()**0)", "(getppidd()**0)", "(getppif()**0)"});


        for (String[] entry: functions) {

            String[] invalidCalls = Arrays.copyOfRange(entry, 2, entry.length);
            for (int i=0;i<invalidCalls.length;i++) {
                invalidCalls[i] = prefix+invalidCalls[i]+suffix;
            }
            Probe functionCall = new Probe(entry[0], 9, invalidCalls);
            functionCall.setEscapeStrings(prefix+entry[1]+suffix);
            functionCall.setRandomAnchor(useRandomAnchor);
            ArrayList<Attack> functionCallResult = fuzz(baseRequestResponse, insertionPoint, basicAttack, functionCall);
            if (functionCallResult.isEmpty() && entry[0].equals("Basic function injection")) {
                break;
            }

            attacks.addAll(fuzz(baseRequestResponse, insertionPoint, basicAttack, functionCall));
        }

        return attacks;
    }

    IScanIssue findReflectionIssues(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Attack basicAttack) {
        String baseValue = insertionPoint.getBaseValue();

        Probe multiFuzz = new Probe("Basic fuzz", 0, "`z'z\"\\", "\\z`z'z\"\\");
        multiFuzz.addEscapePair("\\`z\\'z\\\"\\\\", "\\`z''z\\\"\\\\");
        ArrayList<Attack> attacks = fuzz(baseRequestResponse, insertionPoint, basicAttack, multiFuzz);

        ArrayList<String> potential_delimiters = new ArrayList<>();
        if (Utilities.THOROUGH_MODE || !attacks.isEmpty()) {

            // find the encapsulating quote type: ` ' "
            Probe trailer = new Probe("Backslash", 1, "\\\\\\", "\\");
            trailer.setBase("\\");
            trailer.setEscapeStrings("\\\\\\\\", "\\\\");

            Probe apos = new Probe("String - apostrophe", 3, "z'z", "\\zz'z", "z/'z"); // "z'z'z"
            apos.setBase("'");
            apos.addEscapePair("z\\'z", "z''z");
            apos.addEscapePair("z\\\\\\'z", "z\\''z");

            Probe quote = new Probe("String - doublequoted", 3, "\"", "\\zz\"");
            quote.setBase("\"");
            quote.setEscapeStrings("\\\"");

            Probe backtick = new Probe("String - backtick", 2, "`", "\\z`");
            backtick.setBase("`");
            backtick.setEscapeStrings("\\`");

            Probe[] potential_breakers = {trailer, apos, quote, backtick};

            for (Probe breaker : potential_breakers) {
                ArrayList<Attack> results = fuzz(baseRequestResponse, insertionPoint, basicAttack, breaker);
                if (results.isEmpty()) {
                    continue;
                }
                potential_delimiters.add(breaker.getBase());
                attacks.addAll(results);
            }

            if (potential_delimiters.isEmpty()) {
                Probe quoteSlash = new Probe("Doublequote plus slash", 4, "\"z\\", "z\"z\\");
                quoteSlash.setEscapeStrings("\"a\\zz", "z\\z", "z\"z/");
                attacks.addAll(fuzz(baseRequestResponse, insertionPoint, basicAttack, quoteSlash));

                Probe aposSlash = new Probe("Singlequote plus slash", 4, "'z\\", "z'z\\");
                aposSlash.setEscapeStrings("'a\\zz", "z\\z", "z'z/");
                attacks.addAll(fuzz(baseRequestResponse, insertionPoint, basicAttack, aposSlash));
            }

            if (potential_delimiters.contains("\\")) {
                // todo follow up with [char]/e%00
                Probe regexEscapeAt = new Probe("Regex escape - @", 4, "z@", "\\@z@");
                regexEscapeAt.setEscapeStrings("z\\@", "\\@z\\@");
                attacks.addAll(fuzz(baseRequestResponse, insertionPoint, basicAttack, regexEscapeAt));

                Probe regexEscapeSlash = new Probe("Regex escape - /", 4, "z/", "\\/z/");
                regexEscapeSlash.setEscapeStrings("z\\/", "\\/z\\/");
                attacks.addAll(fuzz(baseRequestResponse, insertionPoint, basicAttack, regexEscapeSlash));
            }

            // find the concatenation character
            String[] concatenators = {"||", "+", " ", ".", "&"};
            ArrayList<String[]> injectionSequence = new ArrayList<>();

            for (String delimiter : potential_delimiters) {
                for (String concat : concatenators) {
                    Probe concat_attack = new Probe("Concatenation: "+delimiter+concat, 7, "z" + concat + delimiter + "z(z" + delimiter + "z");
                    concat_attack.setEscapeStrings("z(z" + delimiter + concat + delimiter + "z");
                    ArrayList<Attack> results = fuzz(baseRequestResponse, insertionPoint, basicAttack, concat_attack);
                    if (results.isEmpty()) {
                        continue;
                    }
                    attacks.addAll(results);
                    injectionSequence.add(new String[]{delimiter, concat});
                }
            }

            // try to invoke a function
            for (String[] injection: injectionSequence) {
                String delim = injection[0];
                String concat = injection[1];
                ArrayList<Attack> functionProbeResults = exploreAvailableFunctions(baseRequestResponse, insertionPoint, basicAttack, delim+concat, concat+delim, true);
                if (!functionProbeResults.isEmpty()) { //  && !functionProbeResults.get(-1).getProbe().getName().equals("Basic function injection")
                    attacks.addAll(functionProbeResults);
                    break;
                }
            }

        }

        Probe interp = new Probe("Interpolation fuzz", 2, "%{{z${{z", "z%{{zz${{z");
        interp.setEscapeStrings("%}}$}}", "}}%z}}$z", "z%}}zz$}}z");
        ArrayList<Attack> interpResults = fuzz(baseRequestResponse, insertionPoint, basicAttack, interp);
        if (!interpResults.isEmpty()) {
            attacks.addAll(interpResults);

            Probe dollarParse = new Probe("Interpolation - dollar", 5, "${{z", "z${{z");
            dollarParse.setEscapeStrings("$}}", "}}$z", "z$}}z");
            ArrayList<Attack>  dollarParseAttack = fuzz(baseRequestResponse, insertionPoint, basicAttack, dollarParse);
            attacks.addAll(dollarParseAttack);

            Probe percentParse = new Probe("Interpolation - percent", 5, "%{{z", "z%{{z");
            percentParse.setEscapeStrings("%}}", "}}%z", "z%}}z");
            ArrayList<Attack> percentParseAttack = fuzz(baseRequestResponse, insertionPoint, basicAttack, percentParse);
            attacks.addAll(percentParseAttack);

            if (!dollarParseAttack.isEmpty() && !percentParseAttack.isEmpty()) {
                attacks.addAll(exploreAvailableFunctions(baseRequestResponse, insertionPoint, basicAttack, "{{", "}}", true));
            }
            else if (!dollarParseAttack.isEmpty()) {
                attacks.addAll(exploreAvailableFunctions(baseRequestResponse, insertionPoint, basicAttack, "${", "}", true));
                attacks.addAll(exploreAvailableFunctions(baseRequestResponse, insertionPoint, basicAttack, "", "", true));
            }
            else if (!percentParseAttack.isEmpty()) {
                attacks.addAll(exploreAvailableFunctions(baseRequestResponse, insertionPoint, basicAttack, "%{", "}", true));
            }
        }

        Attack softBase = new Attack(baseRequestResponse, null, null, "");

        if (!identical(softBase, basicAttack)) {

            if (StringUtils.isNumeric(baseValue)) {

                Probe div0 = new Probe("Divide by 0", 4, "/0", "/00", "/000");
                div0.setEscapeStrings("/1", "-0", "/01", "-00");
                div0.setRandomAnchor(false);
                ArrayList<Attack> div0_results = fuzz(baseRequestResponse, insertionPoint, softBase, div0);

                if (!div0_results.isEmpty()) {
                    attacks.addAll(div0_results);

                    Probe divArith = new Probe("Divide by expression", 5, "/(2-2)", "/(3-3)");
                    divArith.setEscapeStrings("/(2-1)", "/(1*1)");
                    divArith.setRandomAnchor(false);
                    ArrayList<Attack> divArithResult = fuzz(baseRequestResponse, insertionPoint, softBase, divArith);

                    Probe divAbs = new Probe("Divide by function", 7, "/ABS(0)", "/abz(1)", "/abs(00)");
                    divAbs.setEscapeStrings("/ABS(1)", "/abs(1)", "/abs(01)");
                    divAbs.setRandomAnchor(false);
                    ArrayList<Attack> divAbsResult = fuzz(baseRequestResponse, insertionPoint, softBase, divAbs);

                    attacks.addAll(fuzz(baseRequestResponse, insertionPoint, softBase, divArith));
                    attacks.addAll(fuzz(baseRequestResponse, insertionPoint, softBase, divAbs));

                    if (!(divAbsResult.isEmpty() && divArithResult.isEmpty())) {
                        attacks.addAll(exploreAvailableFunctions(baseRequestResponse, insertionPoint, softBase, "/", "", false));
                    }
                }
            }

            if (Utilities.mightBeOrderBy(insertionPoint.getInsertionPointName(), baseValue)) {
                Probe comment = new Probe("Comment injection", 3, "/'z*/**/", "/*/*/z'*/", "/*z'/");
                comment.setEscapeStrings("/*'z*/", "/**z'*/","/*//z'//*/");
                comment.setRandomAnchor(false);
                ArrayList<Attack> commentAttack = fuzz(baseRequestResponse, insertionPoint, softBase, comment);
                if (!commentAttack.isEmpty()) {
                    attacks.addAll(commentAttack);

                    Probe htmlComment = new Probe("HTML comment injection (WAF?)", 4, "<!-zz-->", "<--zz-->", "<!--zz->");
                    htmlComment.setEscapeStrings("<!--zz-->", "<!--z-z-->", "<!-->z<-->");
                    htmlComment.setRandomAnchor(false);
                    ArrayList<Attack> htmlCommentAttack = fuzz(baseRequestResponse, insertionPoint, softBase, htmlComment);
                    attacks.addAll(htmlCommentAttack);

                    Probe procedure = new Probe("MySQL order-by", 7, " procedure analyse (0,0,0)-- -", " procedure analyze (0,0)-- -");
                    procedure.setEscapeStrings(" procedure analyse (0,0)-- -", " procedure analyse (0,0)-- -z");
                    procedure.setRandomAnchor(false);
                    attacks.addAll(fuzz(baseRequestResponse, insertionPoint, softBase, procedure));
                }

                Probe commaAbs = new Probe("Order-by function injection", 5, ",abz(1)", ",abs(0,1)", ",abs()","abs(z)");
                commaAbs.setEscapeStrings(",ABS(1)", ",abs(1)", ",abs(01)"); //  1
                commaAbs.setRandomAnchor(false);
                ArrayList<Attack> commaAbsAttack = fuzz(baseRequestResponse, insertionPoint, softBase, commaAbs);

                if (!commaAbsAttack.isEmpty()) {
                    attacks.addAll(commaAbsAttack);
                    attacks.addAll(exploreAvailableFunctions(baseRequestResponse, insertionPoint, softBase, ",", "", false));
                }
            }

            byte type = insertionPoint.getInsertionPointType();
            boolean isInPath = (type == IScannerInsertionPoint.INS_URL_PATH_FILENAME) ||
                    type == IScannerInsertionPoint.INS_URL_PATH_FOLDER ||
                    type == IScannerInsertionPoint.INS_URL_PATH_REST;
            if (!isInPath && Utilities.mightBeIdentifier(baseValue) && !baseValue.equals("")) {
                Probe dotSlash = new Probe("File Path Manipulation", 3, "../", "z/", "_/", "./../");
                dotSlash.addEscapePair("./z/../", "././", "./././");
                dotSlash.setRandomAnchor(false);
                dotSlash.setPrefix(Probe.PREPEND);
                attacks.addAll(fuzz(baseRequestResponse, insertionPoint, softBase, dotSlash));
            }

            if((!Utilities.THOROUGH_MODE && Utilities.mightBeIdentifier(baseValue)) || (Utilities.THOROUGH_MODE && Utilities.mightBeFunction(baseValue))) {
                Probe functionCall = new Probe("Function hijacking", 6, "sprimtf", "sprintg", "exception", "malloc");
                functionCall.setEscapeStrings("sprintf");
                functionCall.setPrefix(Probe.REPLACE);
                attacks.addAll(fuzz(baseRequestResponse, insertionPoint, softBase, functionCall));
            }
        }

        if (!attacks.isEmpty()) {
            return reportReflectionIssue(attacks.toArray((new Attack[attacks.size()])), baseRequestResponse);
        }
        else {
            return null;
        }
    }
}
