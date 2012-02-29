package org.sharextras.webscripts;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONStringer;
import org.json.JSONWriter;
import org.sharextras.webscripts.connector.HttpOAuthConnector;
import org.springframework.extensions.webscripts.AbstractWebScript;
import org.springframework.extensions.webscripts.Format;
import org.springframework.extensions.webscripts.ScriptRemote;
import org.springframework.extensions.webscripts.ScriptRemoteConnector;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.WebScriptResponse;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Response;

/**
 * Landing page web script for returning from a 3rd party OAuth 1.0a authorization page.
 * 
 * <p>The script receives a verifier code from the 3rd party and is responsible for 
 * exchanging this (plus the temporary request token) for a permanent access token, and
 * then persisting this into the repository and redirecting the user to their original
 * page.</p>
 * 
 * @author Will Abson
 */
public class OAuthReturn extends AbstractWebScript
{
	public static final String USER_TOKEN_URL = "/extras/slingshot/tokenstore/usertoken";
	public static final String PREFS_BASE = "org.alfresco.share.oauth.";
	public static final String PREF_DATA = "data";

	/* URL fragments */
	public static final String URL_PROXY_SERVLET = "/proxy";
	public static final String URL_OAUTH_ACCESSTOKEN_DEFAULT = "/oauth/access_token";
	
	/* URL Parameter names */
	public static final String PARAM_OAUTH_VERIFIER = "oauth_verifier";
	public static final String PARAM_CONNECTOR_ID = "cid";
	public static final String PARAM_ENDPOINT_ID = "eid";
	public static final String PARAM_PROVIDER_ID = "pid";
	public static final String PARAM_REDIRECT_PAGE = "rp";
	
	/* Connector property names */
	public static final String PROP_ACCESS_TOKEN_PATH = "access-token-path";
	
	ScriptRemote scriptRemote;
	ConnectorService connectorService;
	String accessTokenUrl;

	public OAuthReturn()
	{
	}

	@Override
	public void execute(WebScriptRequest req, WebScriptResponse resp) throws IOException
	{
		String verifier = req.getParameter(PARAM_OAUTH_VERIFIER),
			connectorId = req.getParameter(PARAM_CONNECTOR_ID),
			endpointName = req.getParameter(PARAM_ENDPOINT_ID),
			providerName = req.getParameter(PARAM_PROVIDER_ID);

		if (verifier == null || verifier.length() == 0)
		{
			throw new WebScriptException("No OAuth verifier was found");
		}
		if (endpointName == null || endpointName.length() == 0)
		{
			throw new WebScriptException("No connector name was specified");
		}
		if (providerName == null || providerName.length() == 0)
		{
			throw new WebScriptException("No provider name was specified");
		}
		
		String pn = PREFS_BASE + providerName;
		
		Map<String, Object> scriptParams = this.getContainer().getScriptParameters();
		scriptRemote = (ScriptRemote) scriptParams.get("remote");
		ScriptRemoteConnector alfrescoConnector = scriptRemote.connect(), oauthConnector = null;
		if (connectorId != null && connectorId.length() > 0)
		{
			oauthConnector = scriptRemote.connect(connectorId);
		}
		
		String authToken = "", authTokenSecret = "";
		
		// Load the current auth data
		Response authDataResp = alfrescoConnector.get(USER_TOKEN_URL + "?filter=" + pn + "." + PREF_DATA);
		if (authDataResp.getStatus().getCode() == Status.STATUS_OK)
		{
			String authData = authDataResp.getResponse();
			JSONObject authObj = null;
			Map<String, String> authParams = null;
			try
			{
				if (authData.length() > 0)
				{
					authObj = new JSONObject(authData);
					for (String k : pn.split("\\."))
					{
						if (authObj != null)
						{
							try
							{
								authObj = authObj.getJSONObject(k);
							}
							catch (JSONException e)
							{
								authObj = null;
							}
						}
					}
					if (authObj != null && authObj.length() > 0)
					{
						String data = authObj.optString("data", "");
						if (data.length() > 0)
						{
							Map<String, String> dataMap = this.unpackData(data);
							// Unpack the existing parameters
							authToken = dataMap.get(HttpOAuthConnector.OAUTH_TOKEN);
							authTokenSecret = dataMap.get(HttpOAuthConnector.OAUTH_TOKEN_SECRET);
						}
						else
						{
							throw new WebScriptException(Status.STATUS_NOT_FOUND, "No OAuth data could be found for provider " + providerName);
						}
					}
					else
					{
						throw new WebScriptException(Status.STATUS_NOT_FOUND, "No OAuth data could be found for provider " + providerName);
					}

					if (authToken.length() == 0)
					{
						throw new WebScriptException(Status.STATUS_NOT_FOUND, "Request token could not be found");
					}
					if (authTokenSecret.length() == 0)
					{
						throw new WebScriptException(Status.STATUS_NOT_FOUND, "Request token secret could not be found");
					}
					
					authParams = requestAccessToken(endpointName, authToken, authTokenSecret, verifier, req, oauthConnector);
				}
				else
				{
					throw new WebScriptException("Empty response received from OAuth data JSON");
				}
			}
			catch (JSONException e)
			{
				throw new WebScriptException("Could not decode OAuth data JSON response", e);
			}
			/*
			catch (ConnectorServiceException e)
			{
				throw new WebScriptException("Could not locate OAuth connector", e);
			}*/
			
			if (authParams.size() == 0)
			{
				throw new WebScriptException("No data was returned when requesting the access token");
			}
			if (authParams.get(HttpOAuthConnector.OAUTH_TOKEN) == null)
			{
				throw new WebScriptException("No token was returned when requesting the access token");
			}
			if (authParams.get(HttpOAuthConnector.OAUTH_TOKEN_SECRET) == null)
			{
				throw new WebScriptException("No token secret was returned when requesting the access token");
			}
			
			// Persist the data
			Response writeAccessTokenResponse = this.storeAccessTokenData(authParams, pn);
			if (writeAccessTokenResponse.getStatus().getCode() == Status.STATUS_OK)
			{
				String redirectPage = req.getParameter(PARAM_REDIRECT_PAGE).indexOf('/') == 0 ? req.getParameter(PARAM_REDIRECT_PAGE) : "/" + req.getParameter(PARAM_REDIRECT_PAGE),
					redirectLocation = req.getServerPath() + req.getContextPath() + (redirectPage != null ? redirectPage : "");
				resp.addHeader(WebScriptResponse.HEADER_LOCATION, redirectLocation);
				resp.setStatus(Status.STATUS_MOVED_TEMPORARILY);
			}
			else
			{
				throw new WebScriptException("A problem occurred while persisting the OAuth token data");
			}
			
		}
		else
		{
			// TODO if resp is 401 then redirect to original page
			throw new WebScriptException(authDataResp.getStatus().getCode(), "A problem occurred while loading the OAuth token data (code " + authDataResp.getStatus().getCode() + ")");
		}
	}
	
	/**
	 * Unpack OAuth data received in the body of a response
	 * 
	 * @param body
	 * @return
	 */
	private Map<String, String> unpackData(String body)
	{
		String[] pairs = body.split("&");
		Map<String, String> m = new HashMap<String, String>(pairs.length);
		String[] pair;
		for (int i = 0; i < pairs.length; i++)
		{
			pair = pairs[i].split("=");
			if (pair.length == 2)
			{
				m.put(pair[0], pair[1]);
			}
		}
		return m;
	}
	
	private Map<String, String> requestAccessToken(
			String endpointName, String authToken, 
			String authTokenSecret, String verifier,
			WebScriptRequest req,
			ScriptRemoteConnector oauthConnector) throws HttpException, IOException
	{
		Map<String, String> authParams;
		// Add the verifier
		//Connector oauthConnector = connectorService.getConnector(connectorName);
		HttpClient client = new HttpClient();
		
		// TODO Parameterise the access token path
		String postUri = req.getServerPath() + req.getContextPath() + URL_PROXY_SERVLET + "/" + endpointName + getAccessTokenUrl(oauthConnector);
		HttpMethod method = new PostMethod(postUri);
		method.addRequestHeader(HttpOAuthConnector.HEADER_OAUTH_DATA, HttpOAuthConnector.OAUTH_TOKEN + "=\"" + authToken + "\"," + 
				HttpOAuthConnector.OAUTH_TOKEN_SECRET + "=\"" + authTokenSecret + "\"," + PARAM_OAUTH_VERIFIER + "=\"" + verifier + "\"");
		int statusCode = client.executeMethod(method);
		if (statusCode == Status.STATUS_OK)
		{
		    // do something with the input stream, which contains the new parameters in the body
			byte[] responseBody = method.getResponseBody();
		    String tokenResp = new String(responseBody, Charset.forName("UTF-8"));
		    authParams = this.unpackData(tokenResp);
		    return authParams;
		}
		else
		{
			throw new WebScriptException(statusCode, "A problem occurred while requesting the access token");
		}
	}
	
	/**
	 * Store access token data back into the repository
	 * 
	 * @param authParams
	 * @param base
	 * @return
	 */
	private Response storeAccessTokenData(Map<String, String> authParams, String base)
	{
		ScriptRemoteConnector connector = scriptRemote.connect();
		String[] baseParts = base.split("\\.");
		try
		{
			StringBuffer newdata = new StringBuffer();
			JSONWriter currJSON = new JSONStringer().object();
			for (String k : baseParts)
			{
				currJSON.key(k).object();
			}
			// add each auth parameter to currJSON
			for (Map.Entry<String, String> p : authParams.entrySet())
			{
				newdata.append(newdata.length() > 0 ? "&" : "");
				newdata.append(p.getKey() + "=" + p.getValue());
			}
			currJSON.key(PREF_DATA).value(newdata.toString());
			for (int i = 0; i < baseParts.length; i++)
			{
				currJSON.endObject();
			}
			currJSON.endObject();
			String postBody = currJSON.toString();
			
			return connector.post(USER_TOKEN_URL, postBody, Format.JSON.mimetype());
		}
		catch (JSONException e)
		{
			throw new WebScriptException("Could not encode OAuth data in JSON format", e);
		}
	}

	public ScriptRemote getScriptRemote()
	{
		return scriptRemote;
	}

	public void setScriptRemote(ScriptRemote scriptRemote)
	{
		this.scriptRemote = scriptRemote;
	}

	public ConnectorService getConnectorService()
	{
		return connectorService;
	}

	public void setConnectorService(ConnectorService connectorService)
	{
		this.connectorService = connectorService;
	}
	
	public String getAccessTokenUrl()
	{
		return accessTokenUrl != null ? accessTokenUrl : URL_OAUTH_ACCESSTOKEN_DEFAULT;
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

	public void setAccessTokenUrl(String accessTokenUrl)
	{
		this.accessTokenUrl = accessTokenUrl;
	}

}
