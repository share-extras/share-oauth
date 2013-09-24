package org.sharextras.webscripts.connector;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;

import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.Format;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.SimpleCredentialVault;
import org.springframework.extensions.webscripts.connector.User;

/**
 * Vault for storing OAuth 2.0 credentials (an access token and an optional refresh token)
 * 
 * This implementation will only store the credentials specifically required for OAuth 2.0
 * and should not be used for other credentials.
 * 
 * @author wabson
 */
public class OAuth2CredentialVault extends SimpleCredentialVault
{
    private static final String API_STORE_TOKEN = "/oauth/token";
    private static final String ENDPOINT_ALFRESCO = "alfresco";
    private static final String JSON_PROP_PROVIDER_ID = "name";
    private static final String JSON_PROP_ACCESS_TOKEN = "token";
    private static final String JSON_PROP_REFRESH_TOKEN = "refreshToken";
    private static final String PROVIDER_PREFIX = "credentials_";

    private static Log logger = LogFactory.getLog(OAuth2CredentialVault.class);
    
    private static final long serialVersionUID = 4009102141325723492L;
    
    private ConnectorService connectorService;

    public OAuth2CredentialVault(String id)
    {
        super(id);
    }

    @Override
    public void store(Credentials credentials)
    {
        super.store(credentials);
    }

    @Override
    public Credentials retrieve(String endpointId)
    {
        logger.debug("Retrieving credentials");
        Credentials credentials = super.retrieve(endpointId);
        if (credentials == null)
        {
            if (load(endpointId))
            {
                credentials = super.retrieve(endpointId);
            }
        }
        return credentials;
    }

    @Override
    public boolean load()
    {
        // We're not able to load all the persisted endpoint credentials, nor should we!
        return true;
    }

    private boolean load(String endpoint)
    {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        User user = context.getUser();
        String userId = user.getId();
        HttpSession httpSession = ServletUtil.getSession();
        return load(endpoint, httpSession, userId);
    }

    private boolean load(String endpoint, HttpSession session, String userId)
    {
        // build a new remote client
        try
        {
            Connector alfrescoConnector = connectorService.getConnector(ENDPOINT_ALFRESCO, userId, session);
            String providerId = PROVIDER_PREFIX + endpoint, 
                    tokenUrl = API_STORE_TOKEN + "/" + providerId;

            Response response = alfrescoConnector.call(tokenUrl);
            
            if (response.getStatus().getCode() == Status.STATUS_OK)
            {
                if (response.getEncoding() == Format.JSON.mimetype())
                {
                    try
                    {
                        JSONObject jsonObject = new JSONObject(new JSONTokener(response.getText()));
                        String accessToken = jsonObject.getString(JSON_PROP_ACCESS_TOKEN), refreshToken = null;
                        if (jsonObject.has(JSON_PROP_REFRESH_TOKEN) && !"".equals(jsonObject.getString(JSON_PROP_REFRESH_TOKEN)))
                        {
                            refreshToken = jsonObject.getString(JSON_PROP_REFRESH_TOKEN);
                        }
                        Credentials credentials = newCredentials(endpoint);
                        credentials.setProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN, accessToken);
                        credentials.setProperty(OAuth2Credentials.CREDENTIAL_REFRESH_TOKEN, refreshToken);
                    }
                    catch (JSONException e)
                    {
                        // TODO throw an exception
                    }
                }
                else
                {
                    // TODO throw an exception
                }
            }
            
            return true;
        }
        catch (ConnectorServiceException e1)
        {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return false;
        }
        
    }
    
    @Override
    public boolean save()
    {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        User user = context.getUser();
        String userId = user.getId();
        HttpSession httpSession = ServletUtil.getSession();
        return save(httpSession, userId);
    }

    public boolean save(HttpSession session, String userId)
    {
        boolean status = true;
        
        try
        {
            Connector alfrescoConnector = connectorService.getConnector(ENDPOINT_ALFRESCO, userId, session);
            
            // walk through all of the endpoints
            Iterator<String> it = credentialsMap.keySet().iterator();
            while(it.hasNext())
            {
                //remoteClient.setRequestContentType(Format.JSON.mimetype());
                
                String endpointId = (String) it.next(), 
                        providerId = PROVIDER_PREFIX + endpointId, token = "", refreshToken = "";
                
                Credentials credentials = retrieve(endpointId);

                token = (String) credentials.getProperty(OAuth2Credentials.CREDENTIAL_ACCESS_TOKEN);
                refreshToken = (String) credentials.getProperty(OAuth2Credentials.CREDENTIAL_REFRESH_TOKEN);
                
                // TODO check that access token and refresh token have values

                JSONObject persistParams = new JSONObject();
                try
                {
                    persistParams.put(JSON_PROP_PROVIDER_ID, providerId);
                    persistParams.put(JSON_PROP_ACCESS_TOKEN, token);
                    persistParams.put(JSON_PROP_REFRESH_TOKEN, refreshToken);
                }
                catch (JSONException e)
                {
                    // TODO Throw an exception of the correct type
                    status = false;
                }
                
                // Persist the access token
                String tokenUrl = API_STORE_TOKEN + "/" + providerId;
                String postBody = persistParams.toString();
                
                if (logger.isDebugEnabled())
                    logger.debug("Sending token data:\n" + postBody);  
                
                Response response = alfrescoConnector.call(tokenUrl, null, new ByteArrayInputStream(postBody.getBytes("UTF-8")));
                
                // read back the ticket
                if (response.getStatus().getCode() != Status.STATUS_OK)
                {
                    status = false;
                    
                    if (logger.isDebugEnabled())
                        logger.debug("Could not store OAuth 2.0 credentials, received response code: " + response.getStatus().getCode());
                    return false;          
                }
                else
                {
                    if (logger.isDebugEnabled())
                        logger.debug("Stored credentials successfully");  
                }
            }
            return status;
            
        }
        catch (ConnectorServiceException e1)
        {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return false;
        }
        catch (UnsupportedEncodingException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }
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
