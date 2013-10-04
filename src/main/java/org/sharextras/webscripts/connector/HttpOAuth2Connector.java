package org.sharextras.webscripts.connector;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.CredentialVaultProviderException;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.HttpConnector;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.ResponseStatus;

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

    private static final String VAULT_PROVIDER_ID = "oAuth2CredentialVaultProvider";
    private static final String USER_ID = "_alf_USER_ID";

    public static final String PARAM_AUTH_METHOD = "auth-method";

    private static Log logger = LogFactory.getLog(HttpOAuth2Connector.class);
    private ApplicationContext applicationContext;
    
    public HttpOAuth2Connector(ConnectorDescriptor descriptor, String endpoint)
    {
        super(descriptor, endpoint);
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
    
    private String getAuthenticationMethod()
    {
        String descriptorMethod = descriptor.getStringProperty(PARAM_AUTH_METHOD);
        return descriptorMethod != null ? descriptorMethod : AUTH_METHOD_OAUTH;
    }
    
    private boolean hasAccessToken(HttpSession session)
    {
        return !(getConnectorSession() == null || getConnectorSession().getParameter(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN) == null);
    }
    
    @Override
    public Response call(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        try
        {
            Response resp = null;
            HttpSession session = req.getSession();
            if (!hasAccessToken(session))
            {
                loadTokens(uri, req);
            }
            if (logger.isDebugEnabled())
                logger.debug("Loading resource " + uri + " - first attempt");
            if (hasAccessToken(session))
            {
                context.setCommitResponseOnAuthenticationError(false);
                resp = super.call(uri, context, req, res);
                // We could have a cached access token which has been updated in the repo
                if (resp.getStatus().getCode() == ResponseStatus.STATUS_UNAUTHORIZED)
                {
                    if (logger.isDebugEnabled())
                        logger.debug("Loading resource " + uri + " - second attempt");
                    loadTokens(uri, req);
                    // Retry the operation
                    if (hasAccessToken(session))
                    {
                    }
                    context.setCommitResponseOnAuthenticationError(false);
                    resp = super.call(uri, context, req, res);
                }
            }
            else
            {
                // TODO Support unauthenticated access if allowed by the connector instance
                ResponseStatus status = new ResponseStatus();
                status.setCode(ResponseStatus.STATUS_UNAUTHORIZED);
                status.setMessage("No access token is present");
                resp = new Response(status);
                res.setStatus(ResponseStatus.STATUS_UNAUTHORIZED);
                //throw new RuntimeException("No access token is present");
                
            }
            return resp;
        }
        // TODO return responses with errors when we are able to
        catch (CredentialVaultProviderException e)
        {
            /*
             * ResponseStatus status = new ResponseStatus();
            status.setCode(ResponseStatus.STATUS_INTERNAL_SERVER_ERROR);
            status.setMessage("Unable to retrieve OAuth credentials from credential vault");
            status.setException(e);
            return new Response(status);
            */
            throw new RuntimeException("Unable to retrieve OAuth credentials from credential vault", e);
        }
        catch (ConnectorServiceException e)
        {
            /*
            ResponseStatus status = new ResponseStatus();
            status.setCode(ResponseStatus.STATUS_INTERNAL_SERVER_ERROR);
            status.setMessage("Unable to access Alfresco connector in order to retrieve OAuth credentials");
            status.setException(e);
            return new Response(status);
            */
            throw new RuntimeException("Unable to access Alfresco connector in order to retrieve OAuth credentials", e);
        }
    }

    private void loadTokens(String uri, HttpServletRequest request) throws CredentialVaultProviderException, ConnectorServiceException
    {
        logger.debug("Loading OAuth tokens");
        
        HttpSession session = request.getSession();
        if (session != null)
        {
            String userId = (String)session.getAttribute(USER_ID);
            //String endpointId = connectorSession.getEndpointId();
            String endpointId = request.getPathInfo().replaceAll(uri, "").replaceAll("/proxy/", "");

            ConnectorService connectorService = (ConnectorService) applicationContext.getBean("connector.service");

            OAuth2CredentialVault vault = (OAuth2CredentialVault)connectorService.getCredentialVault(session, userId, VAULT_PROVIDER_ID);
            vault.load(endpointId, connectorService.getConnector("alfresco", userId, session));
            Credentials oauthCredentials = vault.retrieve(endpointId);
            if (oauthCredentials != null)
            {
                if (oauthCredentials.getProperty(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN) != null)
                {
                    connectorSession.setParameter(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN, 
                            oauthCredentials.getProperty(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN).toString());
                }
            }
        }
        else
        {
            logger.error("Session should not be null!");
        }
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
