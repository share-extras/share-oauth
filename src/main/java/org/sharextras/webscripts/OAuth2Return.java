package org.sharextras.webscripts;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.extensions.webscripts.Format;
import org.springframework.extensions.webscripts.ScriptRemote;
import org.springframework.extensions.webscripts.ScriptRemoteConnector;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.WebScriptResponse;
import org.springframework.extensions.webscripts.connector.Response;

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
public class OAuth2Return extends OAuthReturn
{
	/* URL fragments */
	public static final String URL_PROXY_SERVLET = "/proxy";
	public static final String URL_OAUTH_ACCESSTOKEN_DEFAULT = "/oauth/access_token";
	
	/* URL Parameter names */
    public static final String PARAM_CODE = "code";
	public static final String PARAM_CONNECTOR_ID = "cid";
	public static final String PARAM_ENDPOINT_ID = "eid";
	public static final String PARAM_PROVIDER_ID = "pid";
	public static final String PARAM_REDIRECT_PAGE = "rp";
	
	/* Connector property names */
	public static final String PROP_ACCESS_TOKEN_PATH = "access-token-path";

    private static Log logger = LogFactory.getLog(OAuth2Return.class);
    
    private String connectorId;
    private String endpointId;
    private String providerId;

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
			connectorId = req.getParameter(PARAM_CONNECTOR_ID),
			endpointName = req.getParameter(PARAM_ENDPOINT_ID),
			tokenName = req.getParameter(PARAM_PROVIDER_ID);
		
		// If values are not supplied as parameters then look these up from the script properties
		
		if (connectorId == null)
		{
		    connectorId = getConnectorId();
		}
        if (endpointName == null)
        {
            endpointName = getEndpointId();
        }
        if (tokenName == null)
        {
            tokenName = getProviderId();
        }

		req.getExtensionPath();
		
		if (code == null || code.length() == 0)
		{
			throw new WebScriptException("No OAuth return code was found");
		}
		if (endpointName == null || endpointName.length() == 0)
		{
			throw new WebScriptException("No connector name was specified");
		}
		if (tokenName == null || tokenName.length() == 0)
		{
			throw new WebScriptException("No token name was specified");
		}
		
		Map<String, Object> scriptParams = this.getContainer().getScriptParameters();
		scriptRemote = (ScriptRemote) scriptParams.get("remote");
		ScriptRemoteConnector alfrescoConnector = scriptRemote.connect(), oauthConnector = null;
		if (connectorId != null && connectorId.length() > 0)
		{
			oauthConnector = scriptRemote.connect(connectorId);
		}

		JSONObject authParams = requestAccessToken(endpointName, code, req, oauthConnector);
		
		if (logger.isDebugEnabled())
		{
            logger.debug("Token data returned");
            try
            {
                logger.debug("Token: " + authParams.getString("access_token"));
                logger.debug("URL: " + authParams.getString("instance_url"));
            }
            catch (JSONException e)
            {
                e.printStackTrace();
            }
		}
		
		// Persist the access token
		String tokenUrl = "/oauth/personal/" + tokenName;
        String postBody = authParams.toString();
        Response writeAccessTokenResponse = alfrescoConnector.post(tokenUrl, postBody, Format.JSON.mimetype());
		if (writeAccessTokenResponse.getStatus().getCode() == Status.STATUS_OK)
		{
			executeRedirect(req, resp);
		}
		else
		{
			throw new WebScriptException("A problem occurred while persisting the OAuth token data");
		}
	}
	
	/**
	 * Obtain a permanent access token from the OAuth service, utilising the OAuth connector to
	 * perform the necessary signing of requests.
	 * 
	 * TODO Check if we can make this more secure by auto-finding the endpoint name
	 * 
	 * @param endpointName
	 * @param verifier
	 * @param req
	 * @param oauthConnector
	 * @return
	 * @throws HttpException
	 * @throws IOException
	 */
	private JSONObject requestAccessToken(
			String endpointName, 
			String verifier,
			WebScriptRequest req,
			ScriptRemoteConnector oauthConnector) throws HttpException, IOException
	{
		HttpClient client = new HttpClient();
		
		String postUri = req.getServerPath() + req.getContextPath() + URL_PROXY_SERVLET + "/" + endpointName + getAccessTokenUrl(oauthConnector);
		PostMethod method = new PostMethod(postUri);
		
		if (logger.isDebugEnabled())
		{
		    logger.debug("Received OAuth return code " + verifier);
		}
		
		method.addParameter("code", verifier);
		method.addParameter("grant_type", "authorization_code");
		method.addParameter("redirect_uri", req.getServerPath() + req.getURL());
		
		int statusCode = client.executeMethod(method);
		if (statusCode == Status.STATUS_OK)
		{
		    // do something with the input stream, which contains the new parameters in the body
			byte[] responseBody = method.getResponseBody();
		    String tokenResp = new String(responseBody, Charset.forName("UTF-8"));
		    if (logger.isDebugEnabled())
	        {
	            logger.debug("Received token response " + tokenResp);
	        }
		    
            try
            {
                JSONObject authResponse = new JSONObject(new JSONTokener(tokenResp));
                return authResponse;
            }
            catch (JSONException e)
            {
                throw new WebScriptException("A problem occurred parsing the JSON response from the provider");
            }
		}
		else
		{
			throw new WebScriptException(statusCode, "A problem occurred while requesting the access token");
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
		String redirectPage = req.getParameter(PARAM_REDIRECT_PAGE).indexOf('/') == 0 ? req.getParameter(PARAM_REDIRECT_PAGE) : "/" + req.getParameter(PARAM_REDIRECT_PAGE),
			redirectLocation = req.getServerPath() + req.getContextPath() + (redirectPage != null ? redirectPage : "");
		resp.addHeader(WebScriptResponse.HEADER_LOCATION, redirectLocation);
		resp.setStatus(Status.STATUS_MOVED_TEMPORARILY);
	}

	public ScriptRemote getScriptRemote()
	{
		return scriptRemote;
	}

	public void setScriptRemote(ScriptRemote scriptRemote)
	{
		this.scriptRemote = scriptRemote;
	}
	
	public String getAccessTokenUrl(ScriptRemoteConnector c)
	{
		if (c != null)
		{
			String tokenPath = c.getDescriptor().getStringProperty(PROP_ACCESS_TOKEN_PATH);
			return tokenPath != null ? tokenPath : getAccessTokenUrl();
		}
		else
		{
			return getAccessTokenUrl();
		}
	}

    public String getConnectorId()
    {
        return connectorId;
    }

    public void setConnectorId(String connectorId)
    {
        this.connectorId = connectorId;
    }

    public String getEndpointId()
    {
        return endpointId;
    }

    public void setEndpointId(String endpointId)
    {
        this.endpointId = endpointId;
    }

    public String getProviderId()
    {
        return providerId;
    }

    public void setProviderId(String providerId)
    {
        this.providerId = providerId;
    }

}
