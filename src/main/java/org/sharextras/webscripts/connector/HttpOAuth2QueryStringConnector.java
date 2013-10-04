package org.sharextras.webscripts.connector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;

public class HttpOAuth2QueryStringConnector extends HttpOAuth2Connector
{
    private final static String PARAM_TOKEN_PARAMETER_NAME = "token-parameter-name";
    private final static String TOKEN_PARAMETER_NAME_DEFAULT = "oauth_token"; // For Chatter

    public HttpOAuth2QueryStringConnector(ConnectorDescriptor descriptor, String endpoint)
    {
        super(descriptor, endpoint);
    }

    @Override
    protected Response callInternal(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        return super.callInternal(applyRequestParameter(uri), context, req, res);
    }

    protected String applyRequestParameter(String uri)
    {
        String accessToken = null;
        if (getConnectorSession() != null)
        {
            // apply alfresco ticket from connector session - i.e. previous login attempt
            accessToken = (String) getConnectorSession().getParameter(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN);
            if (accessToken != null)
            {
                String uriWithToken = uri +
                        (uri.lastIndexOf('?') == -1 ? ("?"+getParameterName()+"="+accessToken) : ("&"+getParameterName()+"="+accessToken));
                
                return uriWithToken;
            }
        }
        return uri;
    }
    
    @Override
    protected void applyRequestAuthentication(RemoteClient remoteClient, ConnectorContext context)
    {
        // Do nothing
    }

    public String getParameterName()
    {
        String descriptorMethod = descriptor.getStringProperty(PARAM_TOKEN_PARAMETER_NAME);
        return descriptorMethod != null ? descriptorMethod : TOKEN_PARAMETER_NAME_DEFAULT;
    }

}
