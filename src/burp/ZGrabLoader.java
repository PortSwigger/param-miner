package burp;

import java.sql.*;
import java.util.Arrays;
import java.util.List;

class ZgrabLoader {

    private Connection conn;
    private Scan scanner;

    ZgrabLoader(Scan scanner) {
        this.scanner = scanner;

        try {
            Class.forName("org.sqlite.JDBC");
            conn = DriverManager.getConnection("jdbc:sqlite:/Users/james/PycharmProjects/zscanpipeline/requests.db");
            //Utilities.out(conn.createStatement().executeQuery("select * from requests").getString(1));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void launchSmugglePipeline() {
        String template = "POST /cowbar?x=123 HTTP/1.1\r\nHost: %d\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n";

        List<String> domains = Arrays.asList("hackxor.net", "store.unity.com", "www.redhat.com");

        scanner.setRequestMethod(this);

        for (String domain: domains) {
            byte[] request = template.replace("%d", domain).getBytes();
            IHttpService service = Utilities.callbacks.getHelpers().buildHttpService(domain, 443, true);
            scanner.doScan(request, service);
        }
        Utilities.out("Scan complete");

    }

    synchronized byte[] getResponse(String host, byte[] request) {
        try {
            PreparedStatement query = conn.prepareStatement("select domain, read from requests where domain = ? and write = ?");
            query.setString(1, host);
            query.setString(2, Utilities.helpers.bytesToString(request));
            ResultSet res = query.executeQuery();

            if (res.isClosed()) {
                Utilities.out("Couldn't find request");
                return null;
            }

            String resp = res.getString(2);
            if (resp == null) {
                Utilities.out("returning timeout...");
                return "".getBytes();
            }

            return resp.getBytes();
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }
}