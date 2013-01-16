package org.sharextras.webscripts.connector;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.EndpointManager;
import org.springframework.extensions.webscripts.connector.HttpConnector;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.ResponseStatus;

public class HttpOAuth2Connector extends HttpConnector
{
    /*
     * OAuth request parameter names
     */
    public static final String OAUTH_CLIENT_ID = "client_id";
    public static final String OAUTH_CLIENT_SECRET = "client_secret";
    public static final String OAUTH_CODE = "code";
    public static final String OAUTH_GRANT_TYPE = "grant_type";
    public static final String OAUTH_REDIRECT_URI = "redirect_uri";
    
    /*
     * Connector parameter names in connector config
     */
    public static final String PARAM_CLIENT_ID = "client-id";
    public static final String PARAM_CLIENT_SECRET = "client-secret";

    private static Log logger = LogFactory.getLog(HttpOAuth2Connector.class);
    
    private String getClientId()
    {
        return descriptor.getStringProperty(PARAM_CLIENT_ID);
    }
    
    private String getClientSecret()
    {
        return descriptor.getStringProperty(PARAM_CLIENT_SECRET);
    }
    
    public HttpOAuth2Connector(ConnectorDescriptor descriptor, String endpoint)
    {
        super(descriptor, endpoint);
    }

    @SuppressWarnings("unchecked")
    public Response call(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        String httpMethod = (context != null ? context.getMethod().toString() : "GET");
        
        if (logger.isDebugEnabled())
            logger.debug("Requested Method: " + httpMethod + " URI: " + uri);
        
        Response response = null;
        if (EndpointManager.allowConnect(this.endpoint))
        {
            RemoteClient remoteClient = initRemoteClient(context);
            
            String baseUrl = uri;
            if (baseUrl.indexOf('?') != -1)
                baseUrl = baseUrl.substring(0, baseUrl.indexOf('?'));
            
            // Build up a Map with all incoming request parameters
            Map<String, String> reqParams = new HashMap<String, String>();
            for (Enumeration<String> pn = req.getParameterNames(); pn.hasMoreElements();)
            {
                String k = pn.nextElement();
                reqParams.put(k, req.getParameter(k));
            }
            if (!reqParams.containsKey(OAUTH_CLIENT_ID))
            {
                // TODO check getClientId() is not null
                reqParams.put(OAUTH_CLIENT_ID, getClientId());
            }
            if (!reqParams.containsKey(OAUTH_CLIENT_SECRET))
            {
                // TODO check getClientSecret() is not null
                reqParams.put(OAUTH_CLIENT_SECRET, getClientSecret());
            }
            
            StringBuffer postStrBuffer = new StringBuffer("?");
            int i = 0;
            for (Map.Entry<String, String> entry : reqParams.entrySet())
            {
                if (i > 0)
                    postStrBuffer.append("&");
                postStrBuffer.append(encodeParameter(entry.getKey())).
                    append("=").
                    append(encodeParameter(entry.getValue()));
                i ++;
            }

            // call client and process response
            response = remoteClient.call(uri, postStrBuffer.toString());
            processResponse(remoteClient, response);
        }
        else
        {
            ResponseStatus status = new ResponseStatus();
            status.setCode(ResponseStatus.STATUS_INTERNAL_SERVER_ERROR);
            response = new Response((String) null, status);
        }
        return response;
    }
    
    /**
     * Percent-encode a parameter for the POST body
     * 
     * @param p Unencoded string
     * @return Encoded text
     */
    private String encodeParameter(String p)
    {
        return URLEncoder.encodeUriComponent(p);
    }

}
