/**
 * Copyright (C) 20010-2011 Share Extras contributors.
 *
 * This file is part of the Share Extras project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sharextras.webscripts.connector;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.EndpointManager;
import org.springframework.extensions.webscripts.connector.HttpConnector;
import org.springframework.extensions.webscripts.connector.HttpOAuthConnector;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.ResponseStatus;

public class HttpOAuthConnector extends HttpConnector
{
	public static final String PARAM_CONSUMER_KEY = "consumer-key";
	public static final String PARAM_CONSUMER_SECRET = "consumer-secret";
	public static final String PARAM_SIGNATURE_METHOD = "signature-method";
	
	public static final String SIGNATURE_METHOD_PLAINTEXT = "PLAINTEXT";
	
    private static Log logger = LogFactory.getLog(HttpOAuthConnector.class);
    
	public HttpOAuthConnector(ConnectorDescriptor descriptor,
			String endpoint) {
		super(descriptor, endpoint);
	}
	
	private String getConsumerKey()
	{
		return descriptor.getStringProperty(PARAM_CONSUMER_KEY);
	}
	
	private String getConsumerSecret()
	{
		return descriptor.getStringProperty(PARAM_CONSUMER_SECRET);
	}
	
	private String getSignatureMethod()
	{
		return descriptor.getStringProperty(PARAM_SIGNATURE_METHOD);
	}
	
	private String generateSignature(Map<String, String> oauthParams)
	{
		if (getSignatureMethod().equals(SIGNATURE_METHOD_PLAINTEXT))
		{
			StringBuffer signatureBuffer = new StringBuffer(getConsumerSecret()).append("%26");
			String tokenSecret = oauthParams.get("oauth_token_secret");
			if (tokenSecret != null && !tokenSecret.equals(""))
			{
				signatureBuffer.append(tokenSecret);
			}
			return signatureBuffer.toString();
		}
		else
		{
			// TODO do we need to throw an exception?
			return null;
		}
	}
	
    public Response call(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        if (logger.isDebugEnabled())
            logger.debug("Requested Method: " + (context != null ? context.getMethod() : "GET") + " URI: " + uri);
        Response response = null;
        if (EndpointManager.allowConnect(this.endpoint))
        {
            RemoteClient remoteClient = initRemoteClient(context);
            
        	String auth = req.getHeader("X-OAuth-Data");
        	if (auth != null && !auth.equals(""))
        	{
        		if (logger.isDebugEnabled())
        			logger.debug("Found OAuth data " + auth);

    			Pattern p = Pattern.compile("(.+)=\"(.+)\"");
        		String[] authParams = auth.split(",");
        		Map<String, String> authMap = new HashMap<String, String>(authParams.length);
        		for (int i = 0; i < authParams.length; i++)
        		{
        			Matcher m = p.matcher(authParams[i]);
        			if (m.matches())
        			{
        				authMap.put(m.group(1), m.group(2));
        			}
				}
        		if (!authMap.containsKey("oauth_consumer_key"))
        		{
        			authMap.put("oauth_consumer_key", getConsumerKey());
        		}
        		if (!authMap.containsKey("oauth_signature"))
        		{
        			authMap.put("oauth_signature", generateSignature(authMap));
        		}
        		
        		StringBuffer authBuffer = new StringBuffer("OAuth ");
        		authBuffer.append("oauth_token").append("=\"").append(authMap.get("oauth_token")).append("\",");
        		for (Map.Entry<String, String> entry : authMap.entrySet())
        		{
					if (!entry.getKey().equals("oauth_token_secret") &&
							!entry.getKey().equals("oauth_signature") &&
							!entry.getKey().equals("oauth_token"))
					{
						authBuffer.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\",");
					}
				}
        		authBuffer.append("oauth_signature").append("=\"").append(authMap.get("oauth_signature")).append("\"");
        		
        		if (logger.isDebugEnabled())
        			logger.debug("Adding Authorization header with data: " + authBuffer.toString());
        		
        		Map<String, String> headers = new HashMap<String, String>(1);
        		headers.put("Authorization", authBuffer.toString());
        		remoteClient.setRequestProperties(headers);
        	}
            
            // call client and process response
            response = remoteClient.call(uri, req, res);
            processResponse(remoteClient, response);
        }
        else
        {
            ResponseStatus status = new ResponseStatus();
            status.setCode(ResponseStatus.STATUS_INTERNAL_SERVER_ERROR);
            response = new Response(status);
        }
        return response;
    }
}