package burp;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;


class DiffingScan {
    
    private ArrayList<Attack> exploreAvailableFunctions(PayloadInjector injector, Attack basicAttack, String prefix, String suffix, boolean useRandomAnchor) {
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
            ArrayList<Attack> functionCallResult = injector.fuzz(basicAttack, functionCall);
            if (functionCallResult.isEmpty() && entry[0].equals("Basic function injection")) {
                break;
            }

            attacks.addAll(injector.fuzz(basicAttack, functionCall));
        }

        return attacks;
    }

    IScanIssue findReflectionIssues(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        
        PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);
        String baseValue = insertionPoint.getBaseValue();
        Attack softBase = new Attack(baseRequestResponse);

        // work out which payloads (if any) are worth trying
        Attack crudeFuzz = injector.buildAttack("`z'z\"${{%{{\\", true);
        if(Utilities.verySimilar(softBase, crudeFuzz)) { return null;  }

        softBase.addAttack(injector.buildAttack(baseValue, false));
        if(Utilities.verySimilar(softBase, crudeFuzz)) { return null;  }

        crudeFuzz.addAttack(injector.buildAttack("\\z`z'z\"${{%{{\\", true));
        if(Utilities.verySimilar(softBase, crudeFuzz)) { return null;  }


        ArrayList<Attack> attacks = new ArrayList<>();
        Attack hardBase = injector.buildAttack("", true);
        if (!Utilities.verySimilar(hardBase, crudeFuzz)) {
            hardBase.addAttack(injector.buildAttack("", true));
        }

        if (!Utilities.verySimilar(hardBase, crudeFuzz)) {

            boolean worthTryingInjections = false;
            if (!Utilities.THOROUGH_MODE) {
                Probe multiFuzz = new Probe("Basic fuzz", 0, "`z'z\"\\", "\\z`z'z\"\\");
                multiFuzz.addEscapePair("\\`z\\'z\\\"\\\\", "\\`z''z\\\"\\\\");
                worthTryingInjections = !injector.fuzz(hardBase, multiFuzz).isEmpty();
            }

            if(Utilities.THOROUGH_MODE || worthTryingInjections) {
                ArrayList<String> potential_delimiters = new ArrayList<>();

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
                    ArrayList<Attack> results = injector.fuzz(hardBase, breaker);
                    if (results.isEmpty()) {
                        continue;
                    }
                    potential_delimiters.add(breaker.getBase());
                    attacks.addAll(results);
                }

                if (potential_delimiters.isEmpty()) {
                    Probe quoteSlash = new Probe("Doublequote plus slash", 4, "\"z\\", "z\"z\\");
                    quoteSlash.setEscapeStrings("\"a\\zz", "z\\z", "z\"z/");
                    attacks.addAll(injector.fuzz(hardBase, quoteSlash));

                    Probe aposSlash = new Probe("Singlequote plus slash", 4, "'z\\", "z'z\\");
                    aposSlash.setEscapeStrings("'a\\zz", "z\\z", "z'z/");
                    attacks.addAll(injector.fuzz(hardBase, aposSlash));
                }

                if (potential_delimiters.contains("\\")) {
                    Probe unicodeEscape = new Probe("Escape sequence - unicode", 3, "\\g0041", "\\z0041");
                    unicodeEscape.setEscapeStrings("\\u0041", "\\u0042");
                    attacks.addAll(injector.fuzz(hardBase, unicodeEscape));

                    Probe regexEscape = new Probe("Escape sequence - regex", 4, "\\g0041", "\\z0041");
                    regexEscape.setEscapeStrings("\\s0041", "\\n0041");
                    attacks.addAll(injector.fuzz(hardBase, regexEscape));

                    // todo follow up with [char]/e%00
                    Probe regexBreakoutAt = new Probe("Regex breakout - @", 5, "z@", "\\@z@");
                    regexBreakoutAt.setEscapeStrings("z\\@", "\\@z\\@");
                    attacks.addAll(injector.fuzz(hardBase, regexBreakoutAt));

                    Probe regexBreakoutSlash = new Probe("Regex breakout - /", 5, "z/", "\\/z/");
                    regexBreakoutSlash.setEscapeStrings("z\\/", "\\/z\\/");
                    attacks.addAll(injector.fuzz(hardBase, regexBreakoutSlash));

                }

                // find the concatenation character
                String[] concatenators = {"||", "+", " ", ".", "&"};
                ArrayList<String[]> injectionSequence = new ArrayList<>();

                for (String delimiter : potential_delimiters) {
                    for (String concat : concatenators) {
                        Probe concat_attack = new Probe("Concatenation: " + delimiter + concat, 7, "z" + concat + delimiter + "z(z" + delimiter + "z");
                        concat_attack.setEscapeStrings("z(z" + delimiter + concat + delimiter + "z", "zx" + delimiter + concat + delimiter + "zy");
                        ArrayList<Attack> results = injector.fuzz(hardBase, concat_attack);
                        if (results.isEmpty()) {
                            continue;
                        }
                        //Utilities.out(results.get(0).getPrint().toString());
                        //Utilities.out(results.get(1).getPrint().toString());
                        attacks.addAll(results);
                        injectionSequence.add(new String[]{delimiter, concat});
                        //break;
                    }

                    Probe jsonValue = new Probe("JSON Injection (value)", 6, "z"+delimiter+","+delimiter+"z"+delimiter+"z"+delimiter+"z",
                            "z"+delimiter+","+delimiter+"z"+delimiter+";"+delimiter+"z",
                            "z"+delimiter+","+delimiter+"z"+delimiter+"."+delimiter+"z");
                    jsonValue.setEscapeStrings("z"+delimiter+","+delimiter+"z"+delimiter+":"+delimiter+"z");
                    attacks.addAll(injector.fuzz(hardBase, jsonValue));

                    Probe jsonKey = new Probe("JSON Injection (key)", 6, "z"+delimiter+":"+delimiter+"z"+delimiter+"z"+delimiter,
                            "z"+delimiter+":"+delimiter+"z"+delimiter+":"+delimiter,
                            "z"+delimiter+":"+delimiter+"z"+delimiter+"."+delimiter);
                    jsonKey.setEscapeStrings("z"+delimiter+":"+delimiter+"z"+delimiter+","+delimiter);
                    attacks.addAll(injector.fuzz(hardBase, jsonKey));
                }



                // try to invoke a function
                for (String[] injection : injectionSequence) {
                    String delim = injection[0];
                    String concat = injection[1];
                    ArrayList<Attack> functionProbeResults = exploreAvailableFunctions(injector, hardBase, delim + concat, concat + delim, true);
                    if (!functionProbeResults.isEmpty()) { //  && !functionProbeResults.get(-1).getProbe().getName().equals("Basic function injection")
                        attacks.addAll(functionProbeResults);
                        break;
                    }
                }

            }

            Probe interp = new Probe("Interpolation fuzz", 2, "%{{z${{z", "z%{{zz${{z");
            interp.setEscapeStrings("%}}$}}", "}}%z}}$z", "z%}}zz$}}z");
            ArrayList<Attack> interpResults = injector.fuzz(hardBase, interp);
            if (!interpResults.isEmpty()) {
                attacks.addAll(interpResults);

                Probe curlyParse = new Probe("Interpolation - curly", 5, "{{z", "z{{z");
                curlyParse.setEscapeStrings("z}}z", "}}z", "z}}");
                ArrayList<Attack> curlyParseAttack = injector.fuzz(hardBase, curlyParse);

                if (!curlyParseAttack.isEmpty()) {
                    attacks.addAll(curlyParseAttack);
                    attacks.addAll(exploreAvailableFunctions(injector, hardBase, "{{", "}}", true));
                }
                else {
                    Probe dollarParse = new Probe("Interpolation - dollar", 5, "${{z", "z${{z");
                    dollarParse.setEscapeStrings("$}}", "}}$z", "z$}}z");
                    ArrayList<Attack> dollarParseAttack = injector.fuzz(hardBase, dollarParse);
                    attacks.addAll(dollarParseAttack);

                    Probe percentParse = new Probe("Interpolation - percent", 5, "%{{z", "z%{{z");
                    percentParse.setEscapeStrings("%}}", "}}%z", "z%}}z");
                    ArrayList<Attack> percentParseAttack = injector.fuzz(hardBase, percentParse);
                    attacks.addAll(percentParseAttack);

                    if (!dollarParseAttack.isEmpty()) {
                        attacks.addAll(exploreAvailableFunctions(injector, hardBase, "${", "}", true));
                        attacks.addAll(exploreAvailableFunctions(injector, hardBase, "", "", true));
                    } else if (!percentParseAttack.isEmpty()) {
                        attacks.addAll(exploreAvailableFunctions(injector, hardBase, "%{", "}", true));
                    }
                }
            }
        }

        // does a request w/random input differ from the base request? (ie 'should I do soft attacks?')
        if (!Utilities.verySimilar(softBase, hardBase)) {

            if (StringUtils.isNumeric(baseValue)) {

                Probe div0 = new Probe("Divide by 0", 4, "/0", "/00", "/000");
                div0.setEscapeStrings("/1", "-0", "/01", "-00");
                div0.setRandomAnchor(false);
                ArrayList<Attack> div0_results = injector.fuzz(softBase, div0);

                if (!div0_results.isEmpty()) {
                    attacks.addAll(div0_results);

                    Probe divArith = new Probe("Divide by expression", 5, "/(2-2)", "/(3-3)");
                    divArith.setEscapeStrings("/(2-1)", "/(1*1)");
                    divArith.setRandomAnchor(false);
                    ArrayList<Attack> divArithResult = injector.fuzz(softBase, divArith);

                    Probe divAbs = new Probe("Divide by function", 7, "/ABS(0)", "/abz(1)", "/abs(00)");
                    divAbs.setEscapeStrings("/ABS(1)", "/abs(1)", "/abs(01)");
                    divAbs.setRandomAnchor(false);
                    ArrayList<Attack> divAbsResult = injector.fuzz(softBase, divAbs);

                    attacks.addAll(injector.fuzz(softBase, divArith));
                    attacks.addAll(injector.fuzz(softBase, divAbs));

                    if (!(divAbsResult.isEmpty() && divArithResult.isEmpty())) {
                        attacks.addAll(exploreAvailableFunctions(injector, softBase, "/", "", false));
                    }
                }
            }

            if (Utilities.mightBeOrderBy(insertionPoint.getInsertionPointName(), baseValue)) {
                Probe comment = new Probe("Comment injection", 3, "/'z*/**/", "/*/*/z'*/", "/*z'/");
                comment.setEscapeStrings("/*'z*/", "/**z'*/","/*//z'//*/");
                comment.setRandomAnchor(false);
                ArrayList<Attack> commentAttack = injector.fuzz(softBase, comment);
                if (!commentAttack.isEmpty()) {
                    attacks.addAll(commentAttack);

                    Probe htmlComment = new Probe("HTML comment injection (WAF?)", 4, "<!-zz-->", "<--zz-->", "<!--zz->");
                    htmlComment.setEscapeStrings("<!--zz-->", "<!--z-z-->", "<!-->z<-->");
                    htmlComment.setRandomAnchor(false);
                    ArrayList<Attack> htmlCommentAttack = injector.fuzz(softBase, htmlComment);
                    attacks.addAll(htmlCommentAttack);

                    Probe procedure = new Probe("MySQL order-by", 7, " procedure analyse (0,0,0)-- -", " procedure analyze (0,0)-- -");
                    procedure.setEscapeStrings(" procedure analyse (0,0)-- -", " procedure analyse (0,0)-- -z");
                    procedure.setRandomAnchor(false);
                    attacks.addAll(injector.fuzz(softBase, procedure));
                }

                Probe commaAbs = new Probe("Order-by function injection", 5, ",abz(1)", ",abs(0,1)", ",abs()","abs(z)");
                commaAbs.setEscapeStrings(",ABS(1)", ",abs(1)", ",abs(01)"); //  1
                commaAbs.setRandomAnchor(false);
                ArrayList<Attack> commaAbsAttack = injector.fuzz(softBase, commaAbs);

                if (!commaAbsAttack.isEmpty()) {
                    attacks.addAll(commaAbsAttack);
                    attacks.addAll(exploreAvailableFunctions(injector, softBase, ",", "", false));
                }
            }

            byte type = insertionPoint.getInsertionPointType();
            boolean isInPath = (type == IScannerInsertionPoint.INS_URL_PATH_FILENAME) ||
                    type == IScannerInsertionPoint.INS_URL_PATH_FOLDER ||
                    type == IScannerInsertionPoint.INS_URL_PATH_REST;

            if (Utilities.THOROUGH_MODE && !isInPath && Utilities.mightBeIdentifier(baseValue) && !baseValue.equals("")) {
                Probe dotSlash = new Probe("File Path Manipulation", 3, "../", "z/", "_/", "./../");
                dotSlash.setEscapeStrings("./", "././", "./././");
                dotSlash.setRandomAnchor(false);
                dotSlash.setPrefix(Probe.PREPEND);
                ArrayList<Attack> filePathManip = injector.fuzz(softBase, dotSlash);
                if (!filePathManip.isEmpty()) {
                    attacks.addAll(filePathManip);
                    Probe normalisedDotSlash = new Probe("File Path Manipulation (normalised)", 4, "../", "z/", "_/", "./../");
                    normalisedDotSlash.setEscapeStrings("./cow/../", "./foo/bar/../../", "./z/../");
                    normalisedDotSlash.setRandomAnchor(false);
                    normalisedDotSlash.setPrefix(Probe.PREPEND);
                    attacks.addAll(injector.fuzz(softBase, normalisedDotSlash));
                }
            }

            if((!Utilities.THOROUGH_MODE && Utilities.mightBeIdentifier(baseValue)) || (Utilities.THOROUGH_MODE && Utilities.mightBeFunction(baseValue))) {
                Probe functionCall = new Probe("Function hijacking", 6, "sprimtf", "sprintg", "exception", "malloc");
                functionCall.setEscapeStrings("sprintf");
                functionCall.setPrefix(Probe.REPLACE);
                attacks.addAll(injector.fuzz(softBase, functionCall));
            }
        }

        if (!attacks.isEmpty()) {
            return Utilities.reportReflectionIssue(attacks.toArray((new Attack[attacks.size()])), baseRequestResponse);
        }
        else {
            return null;
        }
    }
}
