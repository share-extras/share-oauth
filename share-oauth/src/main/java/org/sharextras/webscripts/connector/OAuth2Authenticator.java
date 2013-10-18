package org.sharextras.webscripts.connector;

import java.text.MessageFormat;

import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.AuthenticationException;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.CredentialVaultProviderException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.connector.AbstractAuthenticator;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.ConnectorSession;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.User;

/**
 * Attempts to retrieve a new OAuth 2.0 token using the refresh token, if available
 * 
 * If no refresh token is available, then a 401 response will be sent to the client, 
 * indicating that is is necessary to obtain a new access token.
 * 
 * @author wabson
 */
public class OAuth2Authenticator extends AbstractAuthenticator implements ApplicationContextAware
{
    private ApplicationContext applicationContext;
    
    private static Log logger = LogFactory.getLog(OAuth2Authenticator.class);

    private static final String ENDPOINT_ALFRESCO = "alfresco";
    private static final String VAULT_PROVIDER_ID = "oAuth2CredentialVaultProvider";
    protected static final String POST_LOGIN = "grant_type=refresh_token&refresh_token={0}&client_id={1}";
    //private static final String API_LOGIN = "/api/login";
    //private static final String MIMETYPE_APPLICATION_JSON = "application/json";
    protected static final String MIMETYPE_URLENCODED = "x-www-form-urlencoded";

    public final static String CS_PARAM_ACCESS_TOKEN = "accessToken";
    public final static String CS_PARAM_REFRESH_TOKEN = "refreshToken";
    
    // For Chatter this should be https://login.instance_name/services/oauth2/token
    private String requestTokenUri;
    
    public OAuth2Authenticator()
    {
        super();
        if (logger.isDebugEnabled())
            logger.debug("Creating new OAuth 2.0 authenticator");
    }
    
    /**
     * Sets the Spring application context
     * 
     * @param applicationContext    the Spring application context
     */
    public void setApplicationContext(ApplicationContext applicationContext)
    {
        this.applicationContext = applicationContext;
    }

    @Override
    public ConnectorSession authenticate(String endpoint, Credentials credentials, ConnectorSession connectorSession)
            throws AuthenticationException
    {
        ConnectorSession cs = null;
        
        /*
         * Try to load OAuth tokens from the vault
         * 
         * We cannot use the crendentials that are supplied to the method. These do not contain OAuth credentials
         * because these need to be loaded separately from the persistent store.
         */
        //Credentials oauthCredentials = loadOAuthCredentials(connectorSession.getEndpointId());
        
        Credentials oauthCredentials = null;
        ConnectorService connectorService = (ConnectorService) applicationContext.getBean("connector.service");
        Connector alfrescoConnector;
        try
        {
            alfrescoConnector = connectorService.getConnector(ENDPOINT_ALFRESCO);
            alfrescoConnector.setCredentials(credentials); // Just one set of credentials for the user, so we can steal these to use for the Alfresco connector
            OAuth2CredentialVault vault = new OAuth2CredentialVault("standaloneVault");
            vault.setAlfrescoConnector(alfrescoConnector); // Set the Alfresco connector to use directly - will then bypass the connector service
            oauthCredentials = vault.retrieve(connectorSession.getEndpointId());
        }
        catch (ConnectorServiceException e)
        {
            e.printStackTrace();
        }
        
        if (oauthCredentials != null && oauthCredentials.getProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN) != null)
        {
            // TODO also check that the token has not expired, if we know the expiration date
            credentials.setProperty(CS_PARAM_ACCESS_TOKEN, oauthCredentials.getProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN));
            // signal that this succeeded
            cs = connectorSession;
        }
        else if (oauthCredentials != null && oauthCredentials.getProperty(OAuth2Credentials.CREDENTIAL_REFRESH_TOKEN) != null)
        {
            String refreshToken = (String) oauthCredentials.getProperty(OAuth2Credentials.CREDENTIAL_REFRESH_TOKEN);
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
                    credentials.setProperty(CS_PARAM_ACCESS_TOKEN, accessToken);
                    
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
        return (connectorSession.getParameter(CS_PARAM_ACCESS_TOKEN) != null);
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
    
    /**
     * Load OAuth credentials for the current user from the persistent credential vault
     * 
     * @return
     * @throws AuthenticationException 
     */
    @SuppressWarnings("unused")
    private Credentials loadOAuthCredentials(String endpointId) throws AuthenticationException
    {
        HttpSession httpSession = ServletUtil.getSession();
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        User user = context.getUser();

        ConnectorService connectorService = (ConnectorService) applicationContext.getBean("connector.service");
        
        String userId = user.getId();
        try
        {
            if (connectorService == null)
            {
                throw new AuthenticationException("Unable to load connector service");
            }
            return connectorService.getCredentialVault(httpSession, userId, VAULT_PROVIDER_ID).retrieve(endpointId);
        }
        catch (CredentialVaultProviderException e)
        {
            throw new WebScriptException("Unable to obtain credential vault for OAuth credentials", e);
        }
    }

}
