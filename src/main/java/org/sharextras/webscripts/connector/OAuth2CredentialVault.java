package org.sharextras.webscripts.connector;

import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.webscripts.Format;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.SimpleCredentialVault;

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
    
    private ApplicationContext applicationContext;
    
    /** RemoteClient base bean used to clone beans for use in Authenticators */
    private static ThreadLocal<RemoteClient> remoteClientBase = new ThreadLocal<RemoteClient>();

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
        // build a new remote client
        RemoteClient remoteClient = buildRemoteClient(ENDPOINT_ALFRESCO);
        
        String providerId = PROVIDER_PREFIX + endpoint, 
                tokenUrl = API_STORE_TOKEN + "/" + providerId;

        Response response = remoteClient.call(tokenUrl);
        
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

    @Override
    public boolean save()
    {
        boolean status = true;
        
        // build a new remote client
        RemoteClient remoteClient = buildRemoteClient(ENDPOINT_ALFRESCO);
        
        // walk through all of the endpoints
        Iterator<String> it = credentialsMap.keySet().iterator();
        while(it.hasNext())
        {
            remoteClient.setRequestContentType(Format.JSON.mimetype());
            
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
            
            Response response = remoteClient.call(tokenUrl, postBody);
            
            // read back the ticket
            if (response.getStatus().getCode() != Status.STATUS_OK)
            {
                status = false;
                
                if (logger.isDebugEnabled())
                    logger.debug("Could not store OAuth 2.0 credentials, received response code: " + response.getStatus().getCode());  
                return false;          
            }
        }
        return status;
    }
    
    /**
     * Build a Remote Client instance by retrieving and configuring the "connector.remoteclient" bean.
     * 
     * Copied from class org.springframework.extensions.webscripts.connector.AbstractAuthenticator
     * 
     * @param endpoint  Configured Endpoint ID for the remote client instance
     */
    protected RemoteClient buildRemoteClient(String endpoint)
    {
        RemoteClient client = this.remoteClientBase.get();
        if (client == null)
        {
            // get the Remote Client prototype bean from Spring
            if (this.applicationContext == null)
            {
                throw new IllegalStateException("Application Context must be set programatically for Authenticator.");
            }
            client = (RemoteClient)this.applicationContext.getBean("connector.remoteclient");
            if (client == null)
            {
                throw new IllegalStateException("The 'connector.remoteclient' bean is required by the WebScript framework.");
            }
            // set the object used to clone further bean instances
            this.remoteClientBase.set(client);
        }
        try
        {
            // perform the bean clone from the base instance
            client = (RemoteClient)client.clone();
        }
        catch (CloneNotSupportedException e)
        {
            throw new IllegalStateException("RemoteClient must support clone() method.");
        }
        
        // set the appropriate endpoint ID state for this RemoteClient instance
        client.setEndpoint(endpoint);
        
        return client;
    }

}
