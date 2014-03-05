package org.sharextras.oauth.repo.webscripts;

import java.io.IOException;

import org.alfresco.service.cmr.oauth2.OAuth2CredentialsStoreService;
import org.springframework.extensions.webscripts.AbstractWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.WebScriptResponse;

/**
 * Delete an OAuth 2.0 ticket from the credentials store.
 * 
 * @author Will Abson
 */
public class DeleteOAuthToken extends AbstractWebScript
{

    // Services
    private OAuth2CredentialsStoreService    oauth2CredentialsStoreService;
    
    public void setOauth2CredentialsStoreService(OAuth2CredentialsStoreService oauth2CredentialsStoreService)
    {
        this.oauth2CredentialsStoreService = oauth2CredentialsStoreService;
    }

    @Override
    public void execute(WebScriptRequest req, WebScriptResponse resp)
            throws IOException
    {
        String keyName = req.getServiceMatch().getTemplateVars().get("name");
        
        if (keyName == null || "".equals(keyName))
        {
            throw new WebScriptException("A key name must be specified");
        }
        
        boolean result = oauth2CredentialsStoreService.deletePersonalOAuth2Credentials(keyName);
        
        if (!result)
        {
            throw new WebScriptException(Status.STATUS_NOT_FOUND, "Could not find credentials with name " + keyName);
        }
    }

}
