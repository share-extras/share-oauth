package org.sharextras.webscripts.connector;

import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.Response;

public class MyAlfrescoApiConnector extends HttpOAuth2Connector
{
    private static final String HEADER_ORIGIN = "Origin";

    public MyAlfrescoApiConnector(ConnectorDescriptor descriptor, String endpoint)
    {
        super(descriptor, endpoint);
    }

    @Override
    public Response call(String uri, ConnectorContext context, HttpServletRequest req, HttpServletResponse res)
    {
        return super.call(uri, context, new NoOriginRequest(req), res);
    }

    private static final class NoOriginRequest extends HttpServletRequestWrapper
    {
        public NoOriginRequest(HttpServletRequest request)
        {
            super((HttpServletRequest)request);
        }

        @Override
        public String getHeader(String name)
        {
            return !HEADER_ORIGIN.toLowerCase().equals(name) ? super.getHeader(name) : null;
        }

        @Override
        @SuppressWarnings("rawtypes")
        public Enumeration getHeaderNames()
        {
            Enumeration headers = super.getHeaderNames();
            Vector<String> list = new Vector<String>();
            while(headers.hasMoreElements())
            {
                String name = (String) headers.nextElement();
                if (!HEADER_ORIGIN.toLowerCase().equals(name))
                {
                    list.add(name);
                }
            }
            return list.elements();
        }
    }

}
