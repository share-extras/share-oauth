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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.EndpointManager;
import org.springframework.extensions.webscripts.connector.HttpConnector;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.ResponseStatus;

public class AuthorizationPassthruConnector extends HttpConnector
{
	public static final String HEADER_AUTHORIZATION = "Authorization";
	public static final String HEADER_OAUTH_TOKEN = "X-OAuth-Token";
	
    private static Log logger = LogFactory.getLog(AuthorizationPassthruConnector.class);
    
	public AuthorizationPassthruConnector(ConnectorDescriptor descriptor,
			String endpoint) {
		super(descriptor, endpoint);
	}
	
	public Response call(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
    	String httpMethod = (context != null ? context.getMethod().toString() : "GET");
    	
        if (logger.isDebugEnabled())
            logger.debug("Requested Method: " + httpMethod + " URI: " + uri);
        
        Response response = null;
        if (EndpointManager.allowConnect(this.endpoint))
        {
            RemoteClient remoteClient = initRemoteClient(context);
            
            String authHdr = req.getHeader(HEADER_OAUTH_TOKEN);
            
            if (authHdr != null)
            {
                if (logger.isDebugEnabled())
                    logger.debug("Adding Authorization header with data: " + authHdr);
                
                Map<String, String> headers = new HashMap<String, String>(1);
                headers.put(HEADER_AUTHORIZATION, authHdr);
                
                // Overwrite the old X-OAuth-Data header (we can't explicitly remove it)
                headers.put(HEADER_OAUTH_TOKEN, "");
                
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
            response = new Response((String) null, status);
        }
        return response;
    }

}
