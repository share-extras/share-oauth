package org.sharextras.webscripts.connector;

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
    
    private static final long serialVersionUID = 4009102141325723492L;

    public OAuth2CredentialVault(String id)
    {
        super(id);
    }

    @Override
    public boolean load()
    {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean save()
    {
        // TODO Auto-generated method stub
        return true;
    }

}
