package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class OfferHostnameOverride  implements ContextMenuItemsProvider {
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        List<Component> menuItemList = new ArrayList<>();
        if (event.selectedRequestResponses().isEmpty()) {
            return menuItemList;
        }
        
        HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);
        String serviceHost = requestResponse.httpService().host();
        String hostHeader = requestResponse.request().headerValue("host");
        if (!serviceHost.equals(hostHeader)) {
            JMenuItem retrieveRequestItem = new JMenuItem("Route requests to "+hostHeader + " via "+serviceHost);
            retrieveRequestItem.addActionListener(l -> overrideHostname(serviceHost, hostHeader));
            menuItemList.add(retrieveRequestItem);
        }

        return  menuItemList;
    }

    //  fixme nukes existing hostname overrides QQ
    private static void overrideHostname(String serviceHost, String hostHeader) {
        String ipAddress;
        try {
            ipAddress = InetAddress.getByName(serviceHost).getHostAddress();
        } catch (UnknownHostException e) {
            return;
        }
        String json = "{\"enabled\":true,\"hostname\":\""+hostHeader+"\",\"ip_address\":\""+ipAddress+"\"}"; // {"project_options":{"connections":{"hostname_resolution":[     ]}}}
        String currentSettings = Utilities.montoyaApi.burpSuite().exportProjectOptionsAsJson("project_options.connections.hostname_resolution");
        if (currentSettings.contains("ip_address")) {
            json = currentSettings.replace("]", ","+json+"]");
        } else {
            json = currentSettings.replace("]", json+"]");
        }

        Utilities.montoyaApi.burpSuite().importProjectOptionsFromJson(json);
    }
}
