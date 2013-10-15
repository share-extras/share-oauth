package org.sharextras.webscripts.connector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.surf.exception.CredentialVaultProviderException;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.CredentialVault;
import org.springframework.extensions.webscripts.connector.CredentialVaultProvider;

public class OAuth2CredentialVaultProvider implements CredentialVaultProvider
{
    private ConnectorService connectorService;

    private static Log logger = LogFactory.getLog(OAuth2CredentialVaultProvider.class);

    /**
     * Reflection constructor
     */
    public OAuth2CredentialVaultProvider()
    {
        logger.debug("Creating new OAuth 2.0 credential vault provider");
    }

    @Override
    public CredentialVault provide(String id) throws CredentialVaultProviderException
    {
        logger.debug("Creating new credential vault with ID " + id);
        
        OAuth2CredentialVault vault = new OAuth2CredentialVault(id);
        if (connectorService == null)
        {
            throw new IllegalStateException("Connection service is required by the credential vault.");
        }
        vault.setConnectorService(connectorService);
        return vault;
    }

    @Override
    public String generateKey(String id, String userId)
    {
        logger.debug("Generating key " + id);
        return id;
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
