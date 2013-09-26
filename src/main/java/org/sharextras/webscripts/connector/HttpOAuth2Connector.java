package org.sharextras.webscripts.connector;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.HttpConnector;
import org.springframework.extensions.webscripts.connector.RemoteClient;

/**
 * Connector for connecting to OAuth 2.0-protected resources
 * 
 * TODO Return a 401 straight away if there is no user context? The AuthenticatingConnector will always try the first request
 *      unauthenticated otherwise, and this may not always return a 401 if the service supports anonymous access.
 * 
 * @author wabson
 */
public class HttpOAuth2Connector extends HttpConnector
{
    public static final String HEADER_AUTHORIZATION = "Authorization";
    
    public static final String AUTH_METHOD_OAUTH = "OAuth";
    public static final String AUTH_METHOD_BEARER = "Bearer";
    
    public static final String PARAM_AUTH_METHOD = "auth-method";

    private static Log logger = LogFactory.getLog(HttpOAuth2Connector.class);
    
    public HttpOAuth2Connector(ConnectorDescriptor descriptor, String endpoint)
    {
        super(descriptor, endpoint);
    }
    
    private String getAuthenticationMethod()
    {
        String descriptorMethod = descriptor.getStringProperty(PARAM_AUTH_METHOD);
        return descriptorMethod != null ? descriptorMethod : AUTH_METHOD_OAUTH;
    }
    
    /* (non-Javadoc)
     * @see org.alfresco.connector.HttpConnector#stampCredentials(org.alfresco.connector.RemoteClient, org.alfresco.connector.ConnectorContext)
     */
    @Override
    protected void applyRequestAuthentication(RemoteClient remoteClient, ConnectorContext context)
    {
        String accessToken = null;
        
        // if this connector is managing session info
        if (getConnectorSession() != null)
        {
            // apply alfresco ticket from connector session - i.e. previous login attempt
            accessToken = (String)getConnectorSession().getParameter(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN);
        }
        
        if (accessToken != null)
        {
            String authorization = getAuthenticationMethod() + " " + accessToken;
            if (logger.isDebugEnabled())
                logger.debug("Adding Authorization header " + authorization);
            Map<String, String> headers = new HashMap<String, String>(1);
            headers.put(HEADER_AUTHORIZATION, authorization);
            remoteClient.setRequestProperties(headers);
        }
    }

}
