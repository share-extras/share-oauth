package org.sharextras.webscripts;

import java.io.IOException;
import java.nio.charset.Charset;

import javax.servlet.http.HttpSession;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.sharextras.webscripts.connector.OAuth2Credentials;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.config.RemoteConfigElement.EndpointDescriptor;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.CredentialVaultProviderException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.URLDecoder;
import org.springframework.extensions.webscripts.AbstractWebScript;
import org.springframework.extensions.webscripts.Format;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.WebScriptResponse;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.CredentialVault;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.ResponseStatus;
import org.springframework.extensions.webscripts.connector.User;

/**
 * Landing page web script for returning from a 3rd party OAuth 2.0 authorization page.
 * 
 * <p>The script receives a verifier code from the 3rd party and is responsible for 
 * exchanging this (plus the temporary request token) for a permanent access token, and
 * then persisting this into the repository and redirecting the user to their original
 * page.</p>
 * 
 * @author Will Abson
 */
public class OAuth2Return extends AbstractWebScript
{
    /* URL parameter and placeholder names */
    private static final String PARAM_CODE = "code";
    private static final String PARAM_REDIRECT_PAGE = "rp";
    private static final String PARAM_STATE = "state";
    private static final String PH_ENDPOINT_ID = "endpoint";

    /* Connector property names */
    private static final String PROP_ACCESS_TOKEN_URL = "access-token-url";
    private static final String PROP_CLIENT_ID = "client-id";
    private static final String PROP_CLIENT_SECRET = "client-secret";

    /* Vault provider class */
    public static final String VAULT_PROVIDER_ID = "oAuth2CredentialVaultProvider";

    private static Log logger = LogFactory.getLog(OAuth2Return.class);
    
    private ConnectorService connectorService;

    /**
     * Web Script constructor
     */
    public OAuth2Return()
    {
    }

    @Override
    public void execute(WebScriptRequest req, WebScriptResponse resp) throws IOException
    {
        String code = req.getParameter(PARAM_CODE), // mandatory
                endpointId = req.getServiceMatch().getTemplateVars().get(PH_ENDPOINT_ID);

        if (logger.isDebugEnabled())
        {
            logger.debug("Received OAuth return code " + code);
        }

        if (code == null || code.length() == 0)
        {
            throw new WebScriptException(ResponseStatus.STATUS_BAD_REQUEST, "No OAuth return code was found");
        }
        if (endpointId == null)
        {
            throw new WebScriptException(ResponseStatus.STATUS_BAD_REQUEST, "No endpoint ID was specified");
        }

        EndpointDescriptor epd = getConnectorService().getRemoteConfig().getEndpointDescriptor(endpointId);
        if (epd == null)
        {
            throw new WebScriptException(ResponseStatus.STATUS_NOT_FOUND, "Endpoint " + endpointId + " could not be found");
        }
        String connectorId = epd.getConnectorId();
        if (connectorId == null)
        {
            throw new WebScriptException(ResponseStatus.STATUS_BAD_REQUEST, "Connector name cannot be null");
        }

        // First look up parameters specified on the endpoint
        String tokenUrl = epd.getStringProperty(PROP_ACCESS_TOKEN_URL),
                clientId = epd.getStringProperty(PROP_CLIENT_ID),
                clientSecret = epd.getStringProperty(PROP_CLIENT_SECRET);

        // Use values from the connector descriptor, if not provided on the endpoint
        ConnectorDescriptor cd = getConnectorService().getRemoteConfig().getConnectorDescriptor(connectorId);
        if (cd != null)
        {
            if (tokenUrl == null)
                tokenUrl = cd.getStringProperty(PROP_ACCESS_TOKEN_URL);
            if (clientId == null)
                clientId = cd.getStringProperty(PROP_CLIENT_ID);
            if (clientSecret == null)
                clientSecret = cd.getStringProperty(PROP_CLIENT_SECRET);
        }

        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        User user = context.getUser();
        String userId = user.getId();
        HttpSession httpSession = ServletUtil.getSession();
        CredentialVault credentialVault;
        try
        {
            credentialVault = connectorService.getCredentialVault(httpSession, userId, VAULT_PROVIDER_ID);
        }
        catch (CredentialVaultProviderException e)
        {
            throw new WebScriptException("Unable to obtain credential vault for OAuth credentials", e);
        }

        String accessToken = null, refreshToken = "";

        // TODO return a map or object, not a JSON object here
        JSONObject authParams = requestAccessToken(tokenUrl, clientId, clientSecret, code, req);

        logger.debug("Token data returned");
        try
        {
            // TODO use constants for parameter names
            if (authParams.has("access_token"))
            {
                logger.debug("access_token: " + authParams.getString("access_token"));
                accessToken = authParams.getString("access_token");
            }
            if (authParams.has("instance_url"))
            {
                logger.debug("instance_url: " + authParams.getString("instance_url"));
            }
            if (authParams.has("refresh_token"))
            {
                logger.debug("refresh_token: " + authParams.getString("refresh_token"));
                refreshToken = authParams.getString("refresh_token");
            }
        }
        catch (JSONException e)
        {
            throw new WebScriptException("Error parsing access token response", e);
        }

        if (accessToken == null)
        {
            throw new WebScriptException("No access token was found but this is required");
        }

        // Persist the access token
        Credentials c = credentialVault.retrieve(endpointId);
        if (c == null)
        {
            c = credentialVault.newCredentials(endpointId);
        }
        c.setProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN, accessToken);
        c.setProperty(OAuth2Credentials.CREDENTIAL_REFRESH_TOKEN, refreshToken);
        credentialVault.save();
        
        executeRedirect(req, resp);
    }

    /**
     * Make an external call to the OAuth provider to exchange the temporary code for a more
     * permanent access token.
     * 
     * @param tokenUrl      URL which will be POST'ed to to fetch an access token
     * @param clientId      OAuth client ID
     * @param clientSecret  OAuth client secret
     * @param verifier      Temporary code returned from the OAuth provider, to be exchanged for an access token
     * @param req           The web script request object relating to this request
     * @return
     * @throws HttpException
     * @throws IOException
     */
    private JSONObject requestAccessToken(
            String tokenUrl, 
            String clientId,
            String clientSecret,
            String verifier,
            WebScriptRequest req) throws HttpException, IOException
    {
        if (tokenUrl == null)
        {
            throw new IllegalArgumentException("Parameter 'access-token-url' must be provided on connector");
        }
        if (clientId == null)
        {
            throw new IllegalArgumentException("Parameter 'client-id' must be provided on connector");
        }
        if (clientSecret == null)
        {
            throw new IllegalArgumentException("Parameter 'client-secret' must be provided on connector");
        }
        
        HttpClient client = new HttpClient();
        PostMethod method = new PostMethod(tokenUrl);
        
        if (logger.isDebugEnabled())
        {
            logger.debug("Sending OAuth return code " + verifier + " to " + tokenUrl);
        }
        
        String baseUrl = req.getURL();
        if (baseUrl.indexOf('?') != -1)
            baseUrl = baseUrl.substring(0, baseUrl.indexOf('?'));
        
        method.addParameter("code", verifier);
        method.addParameter("grant_type", "authorization_code");
        method.addParameter("redirect_uri", req.getServerPath() + baseUrl);
        
        // Add client ID and secret if specified in the config
        if (clientId != null)
        {
            method.addParameter("client_id", clientId);
        }
        if (clientSecret != null)
        {
            method.addParameter("client_secret", clientSecret);
        }
        
        // Request JSON response
        method.addRequestHeader("Accept", Format.JSON.mimetype());
        
        int statusCode = client.executeMethod(method);
        
        // errors may be {"error":"invalid_grant","error_description":"expired authorization code"}
        // or {"error":"redirect_uri_mismatch","error_description":"redirect_uri must match configuration"}

        byte[] responseBody = method.getResponseBody();
        String tokenResp = new String(responseBody, Charset.forName("UTF-8"));
        
        // do something with the input stream, which contains the new parameters in the body
        if (logger.isDebugEnabled())
        {
            logger.debug("Received token response " + tokenResp);
        }
        
        try
        {
            JSONObject authResponse = new JSONObject(new JSONTokener(tokenResp));
            if (statusCode == Status.STATUS_OK)
            {
                return authResponse;
            }
            else
            {
                @SuppressWarnings("unused")
                String errorDesc = authResponse.getString("error_description"),
                    errorName = authResponse.getString("error");
                throw new WebScriptException(statusCode, "A problem occurred while requesting the access token" + 
                        (errorDesc != null ? " - " + errorDesc : ""));
            }
        }
        catch (JSONException e)
        {
            throw new WebScriptException("A problem occurred parsing the JSON response from the provider");
        }
        
    }
    
    /**
     * Redirect the user to the location that was specified in the request parameter, or
     * to the webapp context root if this was not found
     * 
     * @param req
     * @param resp
     */
    private void executeRedirect(WebScriptRequest req, WebScriptResponse resp)
    {
        String redirectPage = null, state = req.getParameter(PARAM_STATE);
        if (req.getParameter(PARAM_REDIRECT_PAGE) != null)
        {
            redirectPage = req.getParameter(PARAM_REDIRECT_PAGE).indexOf('/') == 0 ? 
                    req.getParameter(PARAM_REDIRECT_PAGE) : 
                        "/" + req.getParameter(PARAM_REDIRECT_PAGE);
        }
        else if (state != null) // TODO extract into utility method
        {
            if (logger.isDebugEnabled())
                logger.debug("Found state: " + state);
            String rp = null;
            String[] parts = state.split("&");
            for (String s : parts) {
                String[] pair = s.split("=");
                if (pair.length == 2)
                    if (PARAM_REDIRECT_PAGE.equals(URLDecoder.decode(pair[0])))
                        rp = URLDecoder.decode(pair[1]);
            }
            if (rp != null)
                redirectPage = rp.indexOf('/') == 0 ? rp : "/" + rp;
        }
        String redirectLocation = req.getServerPath() + req.getContextPath() + (redirectPage != null ? redirectPage : "");
        if (logger.isDebugEnabled())
            logger.debug("Redirecting user to URL " + redirectLocation);
        resp.addHeader(WebScriptResponse.HEADER_LOCATION, redirectLocation);
        resp.setStatus(Status.STATUS_MOVED_TEMPORARILY);
    }

    public ConnectorService getConnectorService()
    {
        return connectorService;
    }

    public void setConnectorService(ConnectorService connectorService)
    {
        this.connectorService = connectorService;
    }

}
