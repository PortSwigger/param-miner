package burp;

import java.net.URL;
import java.util.Arrays;
import java.util.List;

class LazyRequestInfo implements IRequestInfo {

    byte[] request;
    List<String> headers = null;
    String method = null;
    URL url = null;
    IHttpService service = null;

    public LazyRequestInfo(byte[] request, IHttpService service) {
        this.request = request;
        this.service = service;
    }


    @Override
    public String getMethod() {
        if (method == null) {
            method = Utilities.getMethod(request);
        }

        return method;
    }

    @Override
    public URL getUrl() {
        if (url == null) {
            if (service == null) {
                throw new RuntimeException("Can't get URL from request with no service");
            }
            url = Utilities.getURL(request, service);
        }
        return url;
    }

    @Override
    public List<String> getHeaders() {
        if (headers == null) {
            headers = Arrays.asList(Utilities.getHeaders(request).split("\r\n"));
        }
        return headers;
    }

    @Override
    public List<IParameter> getParameters() {
        throw new RuntimeException("getParameters is not implemented");
    }

    @Override
    public int getBodyOffset() {
        return Utilities.getBodyStart(request);
    }

    @Override
    public byte getContentType() {
        throw new RuntimeException("getContentType is not implemented");
        //return Utilities.getHeader(request, "Content-Type");
    }
}