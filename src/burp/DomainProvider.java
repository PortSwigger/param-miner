package burp;

import burp.Utilities;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

class DomainProvider {
    private Scanner domainFileScanner;

    byte type;
    static final byte SUBDOMAIN = 1;
    static final byte ENDSWITH = 2;
    static final byte STARTSWITH = 3;

    DomainProvider(String domain) {
        this(domain, SUBDOMAIN);
    }

    DomainProvider(String domain, byte type) {
        String domainFilePath;

        switch (type) {
            case SUBDOMAIN ->  domainFilePath = "/Users/james.kettle/data/domains/" + domain;
            case ENDSWITH -> domainFilePath = "/Users/james.kettle/data/endswithdomains/" + domain;
            case STARTSWITH ->  {
                domain = domain.split("[.]", 2)[0];
                domainFilePath = "/Users/james.kettle/data/startswithdomains/" + domain;
            }
            default -> throw new RuntimeException("Invalid type: "+type);
        }

        File domainFile = new File(domainFilePath);
        if (!domainFile.exists()) {
            saveDomainsToFile(domain, domainFilePath, type);
            domainFile = new File(domainFilePath);
        }

        try {
            domainFileScanner = new Scanner(domainFile);
        } catch (FileNotFoundException e) {
            throw new RuntimeException("wtf");
        }
    }

    static void execute(String cmd) {
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"bash", "-c", cmd});
            proc.waitFor(100, TimeUnit.MILLISECONDS);
            Thread.sleep(100);
            proc.destroy();
            Thread.sleep(100);
        }  catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }
    }


    void saveDomainsToFile(String domain, String filePath, byte type) {
        switch (type) {
            case SUBDOMAIN -> {
                String url =  "https://columbus.elmasy.com/api/lookup/"+domain;
                HttpRequestResponse apiResp = Utilities.montoyaApi.http().sendRequest(HttpRequest.httpRequestFromUrl(url).withHeader("Accept", "text/plain"), RequestOptions.requestOptions().withUpstreamTLSVerification());
                PrintWriter out = null;
                try {
                    out = new PrintWriter("/tmp/web-"+domain);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
                if (apiResp.hasResponse() && apiResp.response().statusCode() == 200) {
                    out.print(apiResp.response().bodyToString());
                } else {
                    out.print("");
                }
                out.close();

                String revDomain = new StringBuilder(domain).reverse().toString();
                String cmd = "look '"+revDomain+".' /Users/james.kettle/data/useful_records_sorted | cut -c"+(revDomain.length()+2)+"- | rev | sort | uniq > /tmp/rapid-"+domain;
                execute(cmd);
                cmd = "cat '/tmp/rapid-"+domain + "' '/tmp/web-"+domain+"'  | sort | uniq > '"+filePath+"'";
                execute(cmd);
            }
            case ENDSWITH -> {
                String revDomain = new StringBuilder(domain).reverse().toString();
                String cmd = "look '" + revDomain + "' /Users/james.kettle/data/useful_records_sorted | cut -c" + (revDomain.length() + 1) + "- | grep -E '^[^.]' | rev | sort | uniq | shuf > " + filePath;
                execute(cmd);

            }
            case STARTSWITH -> {
                String cmd = "look '"+domain+"' /Users/james.kettle/data/useful_records_ordered > "+filePath;
                execute(cmd);
            }
        }

    }

    String getNextDomain() {
        if (domainFileScanner == null || !domainFileScanner.hasNextLine()){
            return null;
        }
        String nextDomain = domainFileScanner.nextLine();
        if ("".equals(nextDomain)) {
            nextDomain = getNextDomain();
        }
        return nextDomain;
    }
}