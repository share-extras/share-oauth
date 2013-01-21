package org.sharextras.webscripts.connector;

import java.text.MessageFormat;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.extensions.surf.exception.AuthenticationException;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.AbstractAuthenticator;
import org.springframework.extensions.webscripts.connector.ConnectorSession;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;

/**
 * Attempts to retrieve a new OAuth 2.0 token using the refresh token, if available
 * 
 * If no refresh token is available, then a 401 response will be sent to the client, 
 * indicating that is is necessary to obtain a new access token.
 * 
 * @author wabson
 */
public class OAuth2Authenticator extends AbstractAuthenticator
{
    private static Log logger = LogFactory.getLog(OAuth2Authenticator.class);
    
    private static final String POST_LOGIN = "grant_type=refresh_token&refresh_token={0}&client_id={1}";
    //private static final String API_LOGIN = "/api/login";
    //private static final String MIMETYPE_APPLICATION_JSON = "application/json";
    private static final String MIMETYPE_URLENCODED = "x-www-form-urlencoded";
    
    // For Chatter this should be https://login.instance_name/services/oauth2/token
    private String requestTokenUri;

    @Override
    public ConnectorSession authenticate(String endpoint, Credentials credentials, ConnectorSession connectorSession)
            throws AuthenticationException
    {
        ConnectorSession cs = null;
        
        String refreshToken;
        if (credentials != null && (refreshToken = (String)credentials.getProperty(OAuth2Credentials.CREDENTIAL_REFRESH_TOKEN)) != null)
        {
            // build a new remote client
            // TODO the endoint for authenticating may be different from the general API endpoint if this is delgated
            RemoteClient remoteClient = buildRemoteClient(endpoint);
            
            // POST to the request new access token URL
            remoteClient.setRequestContentType(MIMETYPE_URLENCODED);
            String body = MessageFormat.format(POST_LOGIN, URLEncoder.encodeUriComponent(refreshToken), 
                    URLEncoder.encodeUriComponent(getClientId()));
            
            Response response = remoteClient.call(getRequestTokenUri(), body);
            
            // read back the ticket
            if (response.getStatus().getCode() == Status.STATUS_OK)
            {
                String accessToken;
                try
                {
                    JSONObject json = new JSONObject(response.getResponse());
                    accessToken = json.getString("access_token");
                } 
                catch (JSONException jErr)
                {
                    // the ticket that came back could not be parsed
                    // this will cause the entire handshake to fail
                    throw new AuthenticationException(
                            "Unable to retrieve access token from provider response", jErr);
                }
                
                if (logger.isDebugEnabled())
                    logger.debug("Parsed access token: " + accessToken);
                
                // place the access token back into the credentials and save these
                if (credentials != null)
                {
                    credentials.setProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN, accessToken);
                    
                    // TODO we need to save the credentials at this point - how?
                    
                    // signal that this succeeded
                    cs = connectorSession;
                }
            }
            else
            {
                if (logger.isDebugEnabled())
                    logger.debug("Token refresh failed, received response code: " + response.getStatus().getCode());            
            }
        }
        else if (logger.isDebugEnabled())
        {
            logger.debug("No user credentials available - cannot authenticate.");
        }
        
        return cs;
    }

    @Override
    public boolean isAuthenticated(String endpoint, ConnectorSession connectorSession)
    {
        return true;
    }

    public boolean isAuthenticated(String endpoint, Credentials credentials, ConnectorSession connectorSession)
    {
        return credentials.getProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN) != null;
    }
    
    private String getClientId()
    {
        // TODO implement this method
        return "";
    }
    
    private String getRequestTokenUri()
    {
        return requestTokenUri;
    }

}
