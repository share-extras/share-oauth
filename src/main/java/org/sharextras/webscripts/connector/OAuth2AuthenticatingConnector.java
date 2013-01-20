package org.sharextras.webscripts.connector;

import org.springframework.extensions.webscripts.connector.AuthenticatingConnector;
import org.springframework.extensions.webscripts.connector.Authenticator;
import org.springframework.extensions.webscripts.connector.Connector;

public class OAuth2AuthenticatingConnector extends AuthenticatingConnector
{

    public OAuth2AuthenticatingConnector(Connector connector, Authenticator authenticator)
    {
        super(connector, authenticator);
    }
    
    /**
     * Returns whether the current session is authenticated already.
     * 
     * @return true, if checks if is authenticated
     */
    protected boolean isAuthenticated()
    {
        return ((OAuth2Authenticator) this.authenticator)
                .isAuthenticated(getEndpoint(), getCredentials(), getConnectorSession());        
    }

}
