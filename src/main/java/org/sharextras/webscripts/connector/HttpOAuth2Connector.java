package org.sharextras.webscripts.connector;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
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
import org.springframework.extensions.surf.util.FakeHttpServletResponse;
import org.springframework.extensions.webscripts.Format;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.HttpConnector;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.ResponseStatus;
import org.springframework.extensions.webscripts.json.JSONWriter;

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
    public static final String PARAM_TOKEN_ENDPOINT = "token-source";

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
        super.setApplicationContext(applicationContext);
        this.applicationContext = applicationContext;
    }
    
    private String getAuthenticationMethod()
    {
        String descriptorMethod = descriptor.getStringProperty(PARAM_AUTH_METHOD);
        return descriptorMethod != null ? descriptorMethod : AUTH_METHOD_OAUTH;
    }
    
    protected boolean hasAccessToken(HttpSession session)
    {
        return !(getConnectorSession() == null || getConnectorSession().getParameter(OAuth2Authenticator.CS_PARAM_ACCESS_TOKEN) == null);
    }

    @Override
    public Response call(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        try
        {
            Response resp = null;
            HttpSession session = req.getSession(false); // TODO check session is non-null
            if (!hasAccessToken(session))
            {
                loadTokens(uri, req);
            }

            if (hasAccessToken(session))
            {
                // Wrap the response object, since it gets committed straight away, and we may need to retry
                FakeHttpServletResponse wrappedRes = new FakeHttpServletResponse(res);
                
                // First call
                context.setCommitResponseOnAuthenticationError(false);
                if (logger.isDebugEnabled())
                    logger.debug("Loading resource " + uri + " - first attempt");
                resp = callInternal(uri, context, req, wrappedRes);
                
                if (logger.isDebugEnabled())
                    logger.debug("Response status " + resp.getStatus().getCode() + " " + resp.getStatus().getCodeName());
                
                // We could have a revoked or expired access token cached which has been updated in the repo
                
                if (resp.getStatus().getCode() == ResponseStatus.STATUS_UNAUTHORIZED || 
                        resp.getStatus().getCode() == ResponseStatus.STATUS_FORBIDDEN)
                {
                    if (logger.isDebugEnabled())
                        logger.debug("Loading resource " + uri + " - second attempt");
                    
                    loadTokens(uri, req);
                    
                    // Retry the operation - second call
                    if (hasAccessToken(session))
                    {
                        context.setCommitResponseOnAuthenticationError(true);
                        try
                        {
                            resp = callInternal(uri, context, req, res);

                            if (logger.isDebugEnabled())
                                logger.debug("Response status " + resp.getStatus().getCode() + " " + resp.getStatus().getCodeName());
                        }
                        catch (Throwable t)
                        {
                            writeError(res, ResponseStatus.STATUS_INTERNAL_SERVER_ERROR, 
                                    "ERR_CALLOUT", 
                                    "Encountered error when attempting to reload",
                                    t);
                            return null;
                        }
                    }
                    else
                    {
                        writeError(res, ResponseStatus.STATUS_UNAUTHORIZED, 
                                "NO_TOKEN", 
                                "No access token is present",
                                null);
                        return null;
                    }
                }
                else
                {
                    copyResponseContent(wrappedRes, res, true);
                }
            }
            else
            {
                writeError(res, ResponseStatus.STATUS_UNAUTHORIZED, 
                        "NO_TOKEN", 
                        "No access token is present",
                        null);
                return null;
                
            }
            
            return resp;
        }
        catch (CredentialVaultProviderException e)
        {
            writeError(res, ResponseStatus.STATUS_INTERNAL_SERVER_ERROR, 
                    "ERR_CREDENTIALSTORE", 
                    "Unable to load credential store",
                    e);
            return null;
        }
        catch (ConnectorServiceException e)
        {
            writeError(res, ResponseStatus.STATUS_INTERNAL_SERVER_ERROR, 
                    "ERR_FETCH_CREDENTIALS", 
                    "Unable to retrieve OAuth credentials from credential vault",
                    e);
            return null;
        }
        catch (IOException e)
        {
            writeError(res, ResponseStatus.STATUS_INTERNAL_SERVER_ERROR, 
                    "ERR_COPY_RESPONSE", 
                    "Error encountered copying outputstream",
                    e);
            return null;
        }
    }

    protected Response callInternal(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        return super.call(uri, context, req, res);
    }

    protected void loadTokens(String uri, HttpServletRequest request) throws CredentialVaultProviderException, ConnectorServiceException
    {
        logger.debug("Loading OAuth tokens");
        
        HttpSession session = request.getSession(false);
        if (session != null)
        {
            String userId = (String)session.getAttribute(USER_ID);
            String endpointId = getEndpointId() != null ? getEndpointId() : 
                request.getPathInfo().replaceAll(uri, "").replaceAll("/proxy/", "");

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

    private void copyResponseContent(FakeHttpServletResponse source, HttpServletResponse dest, boolean flush) throws IOException
    {
        dest.setStatus(source.getStatus());
        dest.setCharacterEncoding(source.getCharacterEncoding());
        // Copy headers over
        for (Object hdrname : source.getHeaderNames())
        {
            dest.setHeader((String) hdrname, (String) source.getHeader((String) hdrname));
        }
        dest.getOutputStream().write(source.getContentAsByteArray());
        if (flush)
        {
            dest.flushBuffer();
        }
    }

    private void writeError(HttpServletResponse resp, int status, String id, String message, Throwable e)
    {
        resp.setStatus(status);
        resp.setContentType(Format.JSON.mimetype());
        try
        {
            JSONWriter writer = new JSONWriter(resp.getWriter());
            writer.startObject();
            writer.startValue("error").startObject();
            writer.writeValue("id", id);
            writer.writeValue("message", message);
            if (e != null)
            {
                writer.startValue("exception").startObject();
                writer.writeValue("message", e.getMessage());
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                e.printStackTrace(pw);
                writer.writeValue("stackTrace", sw.toString());
                writer.endObject();
            }
            writer.endObject();
            writer.endObject();
            resp.flushBuffer();
        }
        catch (IOException e1)
        {
            // Unable to get writer from response
            e1.printStackTrace();
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

    public String getEndpointId()
    {
        return descriptor.getStringProperty(PARAM_TOKEN_ENDPOINT);
    }

}
