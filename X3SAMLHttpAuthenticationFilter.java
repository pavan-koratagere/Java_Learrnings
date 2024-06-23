/*      _____ _____
 *     /  ___/ ___/
 *     ! !  / __ \
 *     ! !_/_/_/ /
 *     \_____!__/
 *
 * $convention$
 *
 */

package com.emc.x3.portal.server.filters.authc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.shiro.web.util.WebUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.HTTPUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.emc.common.java.utils.D2CoreBofServicesUtil;
import com.emc.d2.api.utils.StringUtils;
import com.emc.x3.client.common.constants.Constants;
import com.emc.x3.portal.server.filters.X3AuthHttpServletRequest;


/**
 * SAML Http Authentication Filter is used to create the SAML authentication request and 
 * redirect to the IdP to get the SAML response.
 * It will either validate the SAML response if it's half way solution or it will pass the SAML 
 * response to the CS for validation if it's end to end solution
 */
public class X3SAMLHttpAuthenticationFilter extends X3TrustHttpAuthenticationFilter
{
    //~ Static fields/initializers -------------------------------------------------------------------------------------

    private static final Logger LOG = LoggerFactory.getLogger(X3SAMLHttpAuthenticationFilter.class.getName());

    public static final String TYPE = "SAML";
    
    private static final String JKS_PASSWORD_PROP_NAME = "jks.%s.password";
    private static final String JKS_KEY_ENTRY_ALIAS_PROP_NAME = "jks.%s.entry.alias";
    private static final String JKS_KEY_ENTRY_PASSWORD_PROP_NAME = "jks.%s.entry.password";
    private static final String D2_KEYSTORE_WILDCARD = "*";
    private final String SAML_RESPONSE_SCHEMA_FILE = "schema" + File.separator + "saml-schema-protocol-2.0.xsd";
    
    // Stores the "SessionIndex" attribute of "AuthnStatement" XML element in the SAML assertion. 
    // We need to pass the SessionIndex value in the SAML logout request when logging out of IdP.
    public static final String _SAML_SESSION_INDEX = "_SAMLSessionIndex";
    

    //~ Instance fields ------------------------------------------------------------------------------------------------
    private SecureRandomIdentifierGenerator m_id_generator;
    
    private boolean m_init_failed = false;
    
    private String m_idpAuthenticationUrl = null;
    private String m_idpLogoutUrl = null;
    private String m_assertionConsumerServiceUrl = null;
    private String m_logoutResponseEndpointUrl = null;
    private String m_issuer = null;
    private String m_idpTokenSigningCertificate = null;
    private String m_jksLocation = null;
    private String m_serviceProviderIdentifier = null;
    private boolean forceLogOutFromIdp = true;
    private boolean forceAuthentication = false;
	private Signature m_signature = null;
    private boolean m_signature_initialized = false;
    private BasicX509Credential m_serviceProviderCredential = null;
    
    public class SAMLAuthResponseValidateResult {
        boolean isValid;
        boolean tokenExpired;
        
        SAMLAuthResponseValidateResult() {
        	isValid = false;
        	tokenExpired = false;
        }
    }
    
    
    //~ Methods --------------------------------------------------------------------------------------------------------

    /**
     * Constructor
     */
    public X3SAMLHttpAuthenticationFilter()
    {
    	super();
    	
    	try { 
	        m_id_generator = new SecureRandomIdentifierGenerator(); 
	    } catch (NoSuchAlgorithmException e) { 
	        LOG.error("Failed to create the secure random identifier generator: " + e.getMessage());
	        m_init_failed = true;
	    }
    	
    	try 
    	{
            Properties props = System.getProperties();
            props.setProperty(DefaultBootstrap.SYSPROP_HTTPCLIENT_HTTPS_DISABLE_HOSTNAME_VERIFICATION, "true");
			DefaultBootstrap.bootstrap();
		} 
    	catch (ConfigurationException e) 
    	{
			LOG.error("Failed to initialize the OpenSAML library: " + e.getMessage() );
			m_init_failed = true;
		}
    	
    	// Use SHA2 as the security hash algorithm
    	BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
    	config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
    	config.registerSignatureAlgorithmURI("RSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }
    
    /**
     * Processes requests where the subject was denied access.
     * 
     * Send the SAML authentication request to IdP if necessary.
     * Process the SAML response from IdP if it hasn't done it 
     * once already for this http session. 
     *
     * @param request     the incoming servlet request
     * @param response    the outgoing servlet response
     * @return true if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     * @since 1.0
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception
    {
        boolean result = true;
        
        if(isSkipSSORequest(request))
		{
			//It is skipSSO request, so we'll present the user with our standard login screen.
			LOG.info(" onAccessDenied isSkipSSORequest is true ");
			return result;
		}
        
        LOG.debug("X3SAMLHttpAuthenticationFilter.onAccessDenied ::::::::  ");
        boolean isLoginAttempt = isLoginAttempt(request, response);
        LOG.debug("X3SAMLHttpAuthenticationFilter.onAccessDenied   isLoginAttempt  ::::::::  {}", isLoginAttempt);
        if (!m_init_failed && !isLoginAttempt) {
        	
        	LOG.debug("X3SAMLHttpAuthenticationFilter.onAccessDenied initiate SAML Auth  ");
        	
            HttpServletRequest httpRequest = WebUtils.toHttp(request);
            HttpServletResponse httpResponse = WebUtils.toHttp(response);

            String requestUri = httpRequest.getRequestURI();
            // Check if the request is to get the service provider's metadata.xml file
            if (requestUri.contains("getServiceProviderMetadataXML")) {
            	String serviceProviderMetadataXML = getServiceProviderMetadataXML();
            	if (StringUtils.isNullOrEmpty(serviceProviderMetadataXML)) {
            		LOG.debug("Failed to genereate the service provider metadata.xml");
            	} else {
            		LOG.debug("The service provider metadata.xml:");
            		LOG.debug(serviceProviderMetadataXML);
            	}
            	httpResponse.setContentType("text/xml");
            	httpResponse.addHeader("Content-Disposition", "attachment; filename=\"D2ServiceProviderMetadata.xml\"");
            	PrintWriter out = response.getWriter();
            	out.println(serviceProviderMetadataXML);
            	out.close();
            	return false;
            }
            
            // If the request is SAMLLogoutRequest, then perform logout from IdP
            if (requestUri.contains("SAMLLogoutRequest")) 
            {
            	boolean logoutSuccessful = forceLogOutFromIdp ? logoutFromIdP(httpRequest, httpResponse) : logoutFromD2(httpRequest, httpResponse);
            	if (logoutSuccessful) 
            	{
            		LOG.debug("The user is able to log out of D2/IdP successfully");
            	} 
            	else 
            	{
            		LOG.debug("The user failed to log out of D2/IdP");
            	}
            	return false;
            }
        	
            // Try to get the login name on the http session.
            String authLogin = getAuthLogin(httpRequest);  // Used by half way solution

            if (StringUtils.isNullOrEmpty(authLogin)) {
            	
            	LOG.debug("No user name on the Http session yet");

            	// Try to get the SAML response from the request.
     			String strSamlResponse = httpRequest.getParameter("SAMLResponse");
				if (strSamlResponse == null)
				{
					
					// We'll redirect to IdP with the SAML authentication request on the URL.
					// IdP will redirect back with the SAML response.
					if (redirectToIdPForAuthentication(httpRequest, httpResponse)) {
		        		result = false;
		        	} else {
		                setAuthFailed(httpRequest, httpResponse);
		        	}
				}
				else 
				{
	            	// This is a "POST" request that comes from the IdP with 
	            	// SAML response in the body
					LOG.debug("IdP post back with SAML response: " + strSamlResponse);

					XMLObject samlResponseXMLObj = getSAMLResponseXMLObj(strSamlResponse);
					if (samlResponseXMLObj == null)
					{
						setAuthFailed(httpRequest, httpResponse);
					}
					
					if (samlResponseXMLObj instanceof LogoutResponse) 
					{
						LogoutResponse logoutResponse = (LogoutResponse) samlResponseXMLObj;
    	           		boolean valid = validateSAMLLogoutResponse(logoutResponse);	
    	           		if (valid) {
    	           			LOG.debug("The user successfully logged out from IdP");
    	           			
					        // Redirect to the logout URL specified by the RelayState parameter. 
							String relayState = httpRequest.getParameter("RelayState");
							String logoutRedirectUrl = URLDecoder.decode(relayState, "UTF8");
							LOG.debug("The RelayState logout redirect URL is: " + logoutRedirectUrl);
				        	LOG.debug("Redirect to " + logoutRedirectUrl);
				        	httpResponse.sendRedirect(logoutRedirectUrl);
    	           		} else {
    	           			LOG.error("The user failed to log out from IdP");
    	           		}
					} 
					else
					{
			 			Response samlResponse = (Response) samlResponseXMLObj;

			            SAMLAuthResponseValidateResult validateResult = validateSAMLAuthResponse(samlResponse, httpRequest, httpResponse);
						if (validateResult.isValid) {
					        // Redirect to the URI specified by the RelayState parameter
					        // if it's different from the current request URI. 
							String relayState = httpRequest.getParameter("RelayState");
							String originalUri = URLDecoder.decode(relayState, "UTF8");
					        String currentUri = httpRequest.getRequestURI();
					        if (currentUri.compareTo(originalUri) != 0) {
					        	httpResponse.sendRedirect(originalUri);
					        }
						} else {
							LOG.error("Failed to validate the SAML authentication response from IdP");
							setAuthFailed(httpRequest, httpResponse);
						}
					}
				}
            } else {
                // There is already the login name saved on the http session,
                // that means we already performed the SAML authentication once
                // and already got the SAML response back from the IdP.
            	LOG.debug("Login name on the Http session: " + authLogin);
            }
        }
        
        return result;
    }

    /**
     * Construct the request with the login info before continuing to execute the filter chain 
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the filter chain to execute
     * @throws Exception if there is any error executing the chain.
     */
    @Override
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain chain) throws Exception
    {
    	LOG.debug("X3SAMLHttpAuthenticationFilter.executeChain ::::::::  ");
    	
    	if(isSkipSSORequest(request))
    	{
    		LOG.info(" executeChain isSkipSSORequest is true ");
    		super.executeChain(request, response, chain);
    		return;
    	}
    	
        ServletRequest newRequest = request;
        String principalName = getAuthLogin(request);
        boolean isDRL = canConnect(request);
        
        if (principalName != null)
        {
        	if(isDRL)
        	{
        		LOG.debug("X3SAMLHttpAuthenticationFilter.executeChain  SSO Auth Exists and DRL is true ");
        		String loginParameter = request.getParameter(Constants.HTTP_PARAM_LOGIN);
        		String password = request.getParameter(Constants.HTTP_PARAM_PASSWORD);
        		String docbase = request.getParameter(Constants.HTTP_PARAM_DOCBASE);
        		boolean isTrusted = false;
                if (loginParameter != null && loginParameter.equals(principalName))
                {
                	isTrusted = true;
                }	
                password = (isTrusted) ? password : "NotUsed"; 
                newRequest = new X3AuthHttpServletRequest(request, TYPE, docbase, loginParameter, password, isTrusted);
                LOG.debug("X3SAMLHttpAuthenticationFilter.executeChain  setAuthLogin on session ");
                this.setAuthLogin((HttpServletRequest)request, (HttpServletResponse)response, loginParameter);
        	}
        	else
        	{
        		LOG.debug("X3SAMLHttpAuthenticationFilter.executeChain  SSO Auth Exists and not DRL ");
        		newRequest = new X3AuthHttpServletRequest(request, TYPE, getDefaultRepository(), principalName, "NotUsed", true);
        	}
        	
        }	
        else
        {
        	//check is this an iURL 
        	if(isDRL)
        	{
        		LOG.info("X3SAMLHttpAuthenticationFilter.executeChain  SSO Auth Does not Exists and DRL is true ");
        		String loginParameter = request.getParameter(Constants.HTTP_PARAM_LOGIN);
        		String password = request.getParameter(Constants.HTTP_PARAM_PASSWORD);
        		String docbase = request.getParameter(Constants.HTTP_PARAM_DOCBASE);
        		newRequest = new X3AuthHttpServletRequest(request, TYPE, docbase, loginParameter, password, false);
        		
        		LOG.debug("X3SAMLHttpAuthenticationFilter.executeChain else  setAuthLogin on session ");
                this.setAuthLogin((HttpServletRequest)request, (HttpServletResponse)response, loginParameter);
        	}
        	
        }	
        
        super.executeChain(newRequest, response, chain);
    }
    
    public boolean isForceLogOutFromIdp() {
		return forceLogOutFromIdp;
	}

	public void setForceLogOutFromIdp(boolean forceLogOutFromIdp) {
		LOG.info("Set shiro config forceLogOutFromIDP = {}", forceLogOutFromIdp);
		this.forceLogOutFromIdp = forceLogOutFromIdp;
	}

	public boolean isForceAuthentication() {
		return forceAuthentication;
	}

	public void setForceAuthentication(boolean forceAuthentication) {
		this.forceAuthentication = forceAuthentication;
	}

    
    /**
     * Set the identity provider authentication URL based on shiro.ini
     *
     * @param idpUrl identity provider authentication URL
     * @throws Exception 
     **/
    public void setIdpAuthenticationUrl(String idpAuthenticationUrl) throws Exception
    {
        LOG.info("Set shiro config idpAuthenticationUrl = {}", idpAuthenticationUrl);
        m_idpAuthenticationUrl = idpAuthenticationUrl;       
    }
    
    /**
     * Set the identity provider logout URL based on shiro.ini
     *
     * @param idpUrl identity provider logout URL
     * @throws Exception 
     **/
    public void setIdpLogoutUrl(String idpLogoutUrl) throws Exception
    {
        LOG.info("Set shiro config idpLoguotUrl = {}", idpLogoutUrl);
        m_idpLogoutUrl = idpLogoutUrl;       
    }
        
    /**
     * Set the file path to the IdP token signing certificate based on shiro.ini
     *
     * @param idpTokenSigningCertifcation Path to the IdP token signing certificate
     * @throws Exception 
     **/
   public void setIdpTokenSigningCertificate(String idpTokenSigningCertifcate) throws Exception
   {
        LOG.info("Set shiro config idpTokenSigningCertificate = {}", idpTokenSigningCertifcate);
        m_idpTokenSigningCertificate = idpTokenSigningCertifcate;          	
   }
   
	/**
	 * Set the file path to the Java key store used to sign the SAML authentication request
	 *
	 * @param jksLocation Path to a Java key store
	 * @throws Exception 
	 **/
	public void setJksLocation(String jksLocation) throws Exception
	{
	       LOG.info("Set shiro config jksLocation = {}", jksLocation);
	       m_jksLocation = jksLocation;          	
	}
  
	 /**
	  * Set a unique ID that identifies the service provider 
	  *
	  * @param serviceProviderIdentifier Unique ID to identifier the service provider
	  * @throws Exception 
	  **/
	public void setServiceProviderIdentifier(String serviceProviderIdentifier) throws Exception
	{
	      LOG.info("Set shiro config serviceProviderIdentifier = {}", serviceProviderIdentifier);
	      m_serviceProviderIdentifier = serviceProviderIdentifier;          	
	}

    /**
     * Set the assertion consumer service URL based on shiro.ini
     *
     * @param assertionConsumerServiceUrl assertion consumer service URL
     * @throws Exception 
     **/
    public void setAssertionConsumerServiceUrl(String assertionConsumerServiceUrl) throws Exception
    {
        LOG.info("Set shiro config assertionConsumerServiceUrl = {}", assertionConsumerServiceUrl);
        m_assertionConsumerServiceUrl = assertionConsumerServiceUrl;       
    }

    /**
     * Set the logout response endpoint URL based on shiro.ini
     *
     * @param logoutResponseEndpointUrl logout response endpoint URL
     * @throws Exception 
     **/
    public void setLogoutResponseEndpointUrl(String logoutResponseEndpointUrl) throws Exception
    {
        LOG.info("Set shiro config logoutResponseEndpointUrl = {}", logoutResponseEndpointUrl);
        m_logoutResponseEndpointUrl = logoutResponseEndpointUrl;       
    }    
    
    /**
     * Set the issuer based on shiro.ini
     *
     * @param Issuer DOCUMENT ME!
     * @throws Exception 
     **/
    public void setIssuer(String issuer) throws Exception
    {
        LOG.info("Set shiro config Issuer = {}", issuer);
        m_issuer = issuer;       
    }
    
     /**
     * Build a SAML authentication request URL which will be used
     * to redirect to the IdP
     *
     * @return true if successfully redirect to IdP, false otherwise.
     * @throws ConfigurationException configuration exception 
     **/
    private boolean redirectToIdPForAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse) { 
    	boolean result = true;
    	try {
			IssuerBuilder issuerBuilder = new IssuerBuilder();
	        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "saml");
	        issuer.setValue(m_issuer);
	        
	        DateTime issueInstant = new DateTime();
	        
	        AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
	        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
	        if(isForceAuthentication())
	        {
	        	authnRequest.setForceAuthn(new Boolean(true));
	        }
	        else
	        {
	        	authnRequest.setForceAuthn(new Boolean(false));
	        }	
	        authnRequest.setIsPassive(new Boolean(false));
	        authnRequest.setIssueInstant(issueInstant);
	        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
	        authnRequest.setAssertionConsumerServiceURL(m_assertionConsumerServiceUrl);
	        authnRequest.setIssuer(issuer);
	        authnRequest.setID(m_id_generator.generateIdentifier());
	        authnRequest.setVersion(SAMLVersion.VERSION_20);
	        
	        if (!m_signature_initialized) {
	        	m_signature = getServiceProviderSignature();
	        	m_signature_initialized = true;
	        } 
	        if (m_signature != null) {
	        	// If the authentication request is signed, the Destination attribute 
	        	// MUST contain the URL to which the sender has instructed 
	        	// the user agent to deliver the message. 
		        authnRequest.setDestination(m_idpAuthenticationUrl);
	        }
	       
	        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
		    Element authDOM = marshaller.marshall(authnRequest);
	
	        if (LOG.isDebugEnabled())
	        {
	        	LOG.debug(XMLHelper.prettyPrintXML(authDOM));
			}
	
	        	
	        HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpResponse, true);
	        
	        BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context =new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();  
	        
	        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory(); 
	        QName defaultElementName = SingleSignOnService.DEFAULT_ELEMENT_NAME;
	        SingleSignOnService endpoint = (SingleSignOnService)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName); 
	        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
	        endpoint.setLocation(m_idpAuthenticationUrl);
	        endpoint.setResponseLocation(m_assertionConsumerServiceUrl);
	        context.setPeerEntityEndpoint(endpoint); 
        
	        context.setOutboundSAMLMessage(authnRequest);
	        context.setOutboundMessageTransport(responseAdapter);
	        
	    	// Set RelayState to indicate to the SP what URL the SP should 
	    	// redirect to after successful sign on
	    	// e.g. useful in the direct download link case.
	    	String requestUri = httpRequest.getRequestURI();
	    	String queryString = httpRequest.getQueryString();
	    	if (queryString != null) {
	    		requestUri = requestUri.concat('?' + queryString);
	    	}
		    context.setRelayState(requestUri);
	        
	        if (m_signature != null) {
	        	context.setOutboundSAMLMessageSigningCredential(m_signature.getSigningCredential());
	        }
	
	        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	        LOG.debug("Redirecting to IDP");
            encoder.encode(context);
        }
    	catch (Exception e) 
    	{
        	LOG.error("Failed to redirect to IdP: " + e.getMessage());
        	result = false;
        } 
    	
    	return result;
	} 
    
    /**
     * 
     * @param httpRequest
     * @param httpResponse
     * @return
     * @throws IOException 
     */
    public boolean logoutFromD2(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException 
    {
    	LOG.debug("Logging out only from D2 skipping IDP Logout");
    	String userLoginName = null;
    	String sessionIdx = null;
    	for (Cookie cookie : httpRequest.getCookies()) {
    		boolean bClearCookie = false;
            if (cookie.getName().equals("SAMLNameID")) {
            	userLoginName = cookie.getValue();
            	bClearCookie = true;
            }
            else if (cookie.getName().equals("SAMLSessionIndex")) {
            	sessionIdx = cookie.getValue();
            	bClearCookie = true;
            }
            
            if (bClearCookie) {
            	// Remove the cookie after the filter gets the value.
      		  	cookie.setMaxAge(0);
                ESAPI.httpUtilities().addCookie(httpResponse, cookie);
            }
        }
    	if (userLoginName == null || sessionIdx == null) {
    		LOG.error("Can't get the user login name or session index info that's required to logout from D2");
    		return false;
    	}
    	
    	removeAuthLogin(httpRequest);
    	
    	LOG.debug("Logout from D2 Logging logOut Request URI : {} ", httpRequest.getRequestURL());  
    	
    	String logoutRedirectUrl = httpRequest.getParameter("logoutRedirectUrl");
    	if(logoutRedirectUrl != null) //validate that this URL is from WebContext  only
    	{
    		try 
    		{
				String baseURL = getBaseUrl(httpRequest);
				if(!logoutRedirectUrl.startsWith(baseURL))
				{
					LOG.debug("BaseURL : {} , logoutRedirectUrl : {} ", baseURL, logoutRedirectUrl);
					LOG.debug(" Logout URL Context is differnt from the D2 Context URL . make sure logout URL is configured properly");
					throw new RuntimeException("Logout URL Context is differnt from the D2 Context URL . make sure logout URL is configured properly");
				}
			}
    		catch (org.owasp.esapi.errors.ValidationException e) 
    		{
				e.printStackTrace();
			}
    	}	
    	LOG.debug("logoutRedirectUrl Parameter : {} ", logoutRedirectUrl);  
    	
    	String finalLogOutURL = (logoutRedirectUrl == null) ? m_logoutResponseEndpointUrl : logoutRedirectUrl;
    	LOG.debug("Logout from D2 Redirecting to : {} ", finalLogOutURL);    	
    	httpResponse.sendRedirect(finalLogOutURL);
    	return true;
    }
    /**
     * Redirect to IdP to log out of IdP
     * 
     * @param httpRequest servlet request
     * @param httpResponse servlet response
     * @return true if succeeds, false otherwise
     */
    public boolean logoutFromIdP(HttpServletRequest httpRequest, HttpServletResponse httpResponse) { 
    	LOG.debug("Logout from IdP");
    	
    	LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();
    	
    	logoutRequest.setID(m_id_generator.generateIdentifier());
    	logoutRequest.setVersion(SAMLVersion.VERSION_20);
    	
    	DateTime issueInstant = new DateTime();
    	logoutRequest.setIssueInstant(issueInstant);
    	
		IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(m_issuer);
    	logoutRequest.setIssuer(issuer);    	
    	
    	// Get user name login name and session index from the cookie
    	String userLoginName = null;
    	String sessionIdx = null;
    	for (Cookie cookie : httpRequest.getCookies()) {
    		boolean bClearCookie = false;
            if (cookie.getName().equals("SAMLNameID")) {
            	userLoginName = cookie.getValue();
            	bClearCookie = true;
            }
            else if (cookie.getName().equals("SAMLSessionIndex")) {
            	sessionIdx = cookie.getValue();
            	bClearCookie = true;
            }
            
            if (bClearCookie) {
            	// Remove the cookie after the filter gets the value.
      		  	cookie.setMaxAge(0);
                ESAPI.httpUtilities().addCookie(httpResponse, cookie);
            }
        }
    	if (userLoginName == null || sessionIdx == null) {
    		LOG.error("Can't get the user login name or session index info that's required to logout from IdP");
    		return false;
    	}
    	    	
    	NameID nameId = new NameIDBuilder().buildObject();
        nameId.setValue(userLoginName);
    	logoutRequest.setNameID(nameId);
    	LOG.debug("Log user " + userLoginName + "out of the IdP");
    	
    	// We must remove the _AUTH_LOGIN session attribute to 
    	// force the user to authenticate against IdP again when
    	// he/she logs back in.
    	removeAuthLogin(httpRequest);
    	
    	SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
        sessionIndex.setSessionIndex(sessionIdx);
        logoutRequest.getSessionIndexes().add(sessionIndex);
        
    	// set user logout as reason
    	logoutRequest.setReason("urn:oasis:names:tc:SAML:2.0:logout:user");
    	    	
        if (!m_signature_initialized) {
        	m_signature = getServiceProviderSignature();
        	m_signature_initialized = true;
        } 
        if (m_signature != null) {
        	// If the request is signed, the Destination attribute 
        	// MUST contain the URL to which the sender has instructed 
        	// the user agent to deliver the message. 
        	logoutRequest.setDestination(m_idpLogoutUrl);
        }
       
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(logoutRequest);
        Element logoutDOM = null;
		try {
			logoutDOM = marshaller.marshall(logoutRequest);

	        if (LOG.isDebugEnabled()) {
	        	LOG.debug(XMLHelper.prettyPrintXML(logoutDOM));
			}
		} catch (MarshallingException e) {
			LOG.error("Failed to marshal the SAML logout request.", e);
			return false;
		}
     	
        HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpResponse, true);
        
        BasicSAMLMessageContext<SAMLObject, LogoutRequest, SAMLObject> context = 
        		new BasicSAMLMessageContext<SAMLObject, LogoutRequest, SAMLObject>();  
        
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory(); 
        QName defaultElementName = SingleLogoutService.DEFAULT_ELEMENT_NAME;
        SingleLogoutService endpoint = (SingleLogoutService)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName); 
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(m_idpLogoutUrl);
        endpoint.setResponseLocation(m_logoutResponseEndpointUrl);
        context.setPeerEntityEndpoint(endpoint); 
    
        context.setOutboundSAMLMessage(logoutRequest);
        context.setOutboundMessageTransport(responseAdapter);
        
    	// Set RelayState to indicate to the SP what URL the SP should 
    	// redirect to after successful logout 
    	String logoutRedirectUrl = httpRequest.getParameter("logoutRedirectUrl");
    	LOG.debug("Set relayState to ", logoutRedirectUrl);
	    context.setRelayState(logoutRedirectUrl);
	    
        if (m_signature != null) {
        	context.setOutboundSAMLMessageSigningCredential(m_signature.getSigningCredential());
        }

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        LOG.debug("Redirecting to IDP to logout");
        try {
			encoder.encode(context);
		} catch (MessageEncodingException e) {
			LOG.error("Failed to encode and send the SAML logout request to IdP", e);
			return false;
		}
        
        return true;	
    }
       
    /**
     * Get the service provider signature from the Java key store
     *
     * @Return service provider signature or null if failed to create the signature object
     **/    
     private Signature getServiceProviderSignature() {
    	if (StringUtils.isNullOrEmpty(m_jksLocation))
    		return null;
    	
     	Signature signature = null;
    	FileInputStream fileInputStream = null;
    	try { 
    	   	String jksPassword = null;
        	String jksKeyEntryAlias = null;
        	String jksKeyEntryPassword = null;
        	
        	Map<String, String> secureProperties = D2CoreBofServicesUtil.getSecureProperties();
    		
        	// Try to get the service provider specific password/alias using the service provider identifier
        	if (!StringUtils.isNullOrEmpty(m_serviceProviderIdentifier)) {
        		jksPassword = secureProperties.get(String.format(JKS_PASSWORD_PROP_NAME, m_serviceProviderIdentifier));
        		jksKeyEntryAlias = secureProperties.get(String.format(JKS_KEY_ENTRY_ALIAS_PROP_NAME, m_serviceProviderIdentifier));
        		jksKeyEntryPassword = secureProperties.get(String.format(JKS_KEY_ENTRY_PASSWORD_PROP_NAME, m_serviceProviderIdentifier));
        	}
        	
        	// If the service provider specific password/alias is not defined in D2 key store, 
        	// try to see if there is one defined for all service providers
        	if (StringUtils.isNullOrEmpty(jksPassword)) {
        		jksPassword = secureProperties.get(String.format(JKS_PASSWORD_PROP_NAME, D2_KEYSTORE_WILDCARD));
        	}
        	if (StringUtils.isNullOrEmpty(jksKeyEntryAlias)) {
        		jksKeyEntryAlias = secureProperties.get(String.format(JKS_KEY_ENTRY_ALIAS_PROP_NAME, D2_KEYSTORE_WILDCARD));   		
        	}
        	if (StringUtils.isNullOrEmpty(jksKeyEntryPassword)) {
        		jksKeyEntryPassword = secureProperties.get(String.format(JKS_KEY_ENTRY_PASSWORD_PROP_NAME, D2_KEYSTORE_WILDCARD));
        	}
        	
        	if (StringUtils.isNullOrEmpty(jksPassword) ||
        		StringUtils.isNullOrEmpty(jksKeyEntryAlias) ||
        		StringUtils.isNullOrEmpty(jksKeyEntryPassword)) 
        	{
        		LOG.error("Not able to find the jks pasword, jks key entry alias or jks key entry password from D2 keystore.");
        		return null;
        	}
        	
		    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); 
		    fileInputStream = new FileInputStream(new File(m_jksLocation));
		    keyStore.load(fileInputStream, jksPassword.toCharArray());

		    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(jksKeyEntryAlias, new KeyStore.PasswordProtection(jksKeyEntryPassword.toCharArray()));
		    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		    X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
		    
		    m_serviceProviderCredential = new BasicX509Credential();
		    m_serviceProviderCredential.setEntityCertificate(certificate);
		    m_serviceProviderCredential.setPrivateKey(privateKey);
		 
		    signature = (Signature) org.opensaml.xml.Configuration.getBuilderFactory().getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME)
		    		.buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);
		    signature.setSigningCredential(m_serviceProviderCredential);
		    signature.setSignatureAlgorithm("SHA256");
		    
		    SecurityConfiguration securityConfiguration = Configuration.getGlobalSecurityConfiguration();
		    String keyInfoGeneratorProfile = null;
		    SecurityHelper.prepareSignatureParams(signature, m_serviceProviderCredential, securityConfiguration, keyInfoGeneratorProfile);
    	} catch(Exception e)  
    	{
    		LOG.error("Failed to get the signature to sign the SAML authentication request: " + e.getMessage());
    		LOG.error(e.getStackTrace().toString());
    		e.printStackTrace();
     	}
    	finally {
     		try {
     			if(fileInputStream != null)
     				fileInputStream.close();
     		}catch(Exception e) {
     			LOG.error("{}", e);
     		}
     	}
    	
    	return signature;
	 }

     /**
      * Convert the SAML response string to a XML object 
      *
      * @return XML object representation of the SAML response 
      **/
 	private XMLObject getSAMLResponseXMLObj(String responseMessage) 
 	{ 		
 		try 
 		{		
 			byte[] base64DecodedResponse = Base64.decode(responseMessage);
 			ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);
 			Element documentElement = validateSAMLResponseSchema(is);
 			if(documentElement != null)
 			{
 				//For XSW-5 attack check if intruders inserted more than one Assertion tag
 				NodeList assertionNodeList = documentElement.getElementsByTagName("Assertion");
 				LOG.debug(" No of Assertion Elements in SAML Response " + assertionNodeList.getLength());
 				if(assertionNodeList.getLength() > 1)
 				{
 					LOG.error(" SAML Response got Multiple Assertions, possibly due to Intrusion, stopping SAML response validation");
 					return null;	
 				}
 				UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
 	 			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(documentElement);
 	 			XMLObject responseXmlObj = unmarshaller.unmarshall(documentElement);
 	 			LOG.debug(XMLHelper.prettyPrintXML(documentElement));
 	 			return responseXmlObj;
 			}
		}
 		catch (Exception e)
 		{
			LOG.error("Fail to get the SAML response object");
			LOG.error("Reason: " + e.getMessage());
			return null;
		} 
 		return null;
 	}
 	
 	private Element validateSAMLResponseSchema(InputStream  samlResponseStream)
 	{
 		InputStream schemaInputStream = null;
 		try
 		{
 			schemaInputStream = X3SAMLHttpAuthenticationFilter.class.getClassLoader().getResourceAsStream(SAML_RESPONSE_SCHEMA_FILE);
 			LOG.debug(" schemaInputStream : {} " + schemaInputStream );
 			
 			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
 			factory.setNamespaceAware(true);
 			factory.setValidating(true);
 			factory.setExpandEntityReferences(false);
 			
 			factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage", XMLConstants.W3C_XML_SCHEMA_NS_URI);
 			factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource",	new InputSource(schemaInputStream));
 			
 			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
 			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
 			factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
 			factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
 			
 			DocumentBuilder db = factory.newDocumentBuilder();
 			db.setEntityResolver(new SamlEntityResolver());
 			SamlErrorHandler errorHandler = new SamlErrorHandler();
 			db.setErrorHandler(errorHandler);
 			
 			Document document = db.parse(samlResponseStream);
 			if(errorHandler.isErrorOccured())
 			{
 				LOG.error(" SAML Response Schema validation failed");
 				return null;
 			}
 			else
 			{
 				LOG.debug("  SAML Response Schema validation passed");
 				Element element = document.getDocumentElement();
 				return element;		
 			}
 		}
 		catch(Exception e)
 		{
 			LOG.error(" Error occured while validating SAML response with Schema ", e);
 			return null;
 		}
 		finally
 		{
 			if(schemaInputStream != null)
 			{
 				try {
					schemaInputStream.close();
				} catch (IOException e) {
					LOG.error(" Error occured while closing the Schema Inputstream", e);
				}
 			}
 			if(samlResponseStream != null)
 			{
 				try {
 					samlResponseStream.close();
				} catch (IOException e) {
					LOG.error(" Error occured while closing the samlResponse Inputstream", e);
				}
 			}	
 		}
 	}
 	
 	/**
 	 * Validate the signature inside the SAML response
 	 * @param signature signature
 	 * @return true if valid, false otherwise
 	 */
 	private boolean validateSAMLResponseSignature(Signature signature) {
		boolean success = false;
		LOG.debug("Validating signature with certificate: " + m_idpTokenSigningCertificate);
		File certificateFile = new File(m_idpTokenSigningCertificate);
		CertificateFactory certificateFactory;
		SignatureValidator signatureValidator = null;
		X509EncodedKeySpec publicKeySpec = null;
		FileInputStream certInputStream = null;
		try 
		{
			certInputStream = new FileInputStream(certificateFile);
			certificateFactory = CertificateFactory	.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
			publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());
		} 
		catch (CertificateException ce) 
		{
			LOG.error("Signature verificaton: Failure");
			LOG.error("Reason: " + ce.getMessage());
		} catch (FileNotFoundException e) 
		{
			LOG.error("Signature verificaton: Failure");
			LOG.error("Reason: " + e.getMessage());
		}
		finally
		{
			try{
				if(certInputStream != null)
				{
					certInputStream.close();
				}
			}
			catch(Exception e){
				LOG.error("{}", e);
			}
		}

		KeyFactory keyFactory;

		try 
		{
			keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			BasicX509Credential publicCredential = new BasicX509Credential();
			publicCredential.setPublicKey(publicKey);
			signatureValidator = new SignatureValidator(publicCredential);
			signatureValidator.validate(signature);
			LOG.debug("Signature verification: Success");
			success = true;
		}
		catch (ValidationException | NoSuchAlgorithmException | InvalidKeySpecException e) 
		{
			LOG.error("Invalid Signature");
			LOG.error("Reason: " + e.getMessage());
		}

		if (!success) {
			LOG.error("Signature doesn't match with any of the available certificates");
		} 
		
		return success;
 	}
	
    /**
     * Validate the SAML authentication response
     *
     * @return true if it's valid, false otherwise  
     **/
	private SAMLAuthResponseValidateResult validateSAMLAuthResponse(Response samlresponse, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
		SAMLAuthResponseValidateResult validateResult = new SAMLAuthResponseValidateResult();
		
		try {			
			// checking the status of response
			String statusCode = samlresponse.getStatus().getStatusCode()
					.getValue();
			LOG.debug("Response status: " + statusCode);
			if (!statusCode.equals(StatusCode.SUCCESS_URI)) {
				StatusMessage statusMessage = samlresponse.getStatus().getStatusMessage();
	            LOG.error("Status code is not success");
				if (statusMessage != null) {
					String statusMessageText = null;
		            statusMessageText = statusMessage.getMessage();
	                LOG.error("Reason: " + statusMessageText);
	            }
				LOG.error("Authentication failure");
				return validateResult;
			}

			// validating the signature
			Assertion assertion = null;
			Signature signature = null;// = samlresponse.getSignature();
			List<Assertion> assertionList = samlresponse.getAssertions();
			if (assertionList.isEmpty()) {
				List<EncryptedAssertion> encassertionList = samlresponse
						.getEncryptedAssertions();
				if (encassertionList.isEmpty()) {
					LOG.error("Problem with retrieveing assertion/encrypted assertion from the provided SAML response");
					LOG.error("Authentication failure");
					return validateResult;
				} else {
					LOG.error("Encrypted Assertion is not supported right now. Please turn off encrypted assertion at the IdP");
					return validateResult;
				}
			}
			assertion = assertionList.get(0);
			if (assertion == null) {
				LOG.error("The Response must contain at least one Assertion");
				LOG.error("Authentication failure");
				return validateResult;
			}

			if (!(assertion.isSigned() || samlresponse.isSigned())) {
				LOG.error("Either assertion or response has to be signed ");
				LOG.error("Authentication failure");
				return validateResult;
			}
			signature = assertion.getSignature();
			if (signature == null) {
				signature = samlresponse.getSignature();
				if (signature == null) {
					LOG.error("Problem  retrieving signature from the provided SAML response.");
					LOG.error("Authentication failure");
					return validateResult;
				}
			}

			boolean validSignature = this.validateSAMLResponseSignature(signature);
			if (!validSignature) {
				return validateResult;
			}

			// checking the token validity
			if (assertion.getConditions() != null) {
				DateTime validFrom = assertion.getConditions().getNotBefore();
				DateTime validTill = assertion.getConditions()
						.getNotOnOrAfter();
				if (validFrom != null && validFrom.isAfterNow()) {
					LOG.error("Assertion is not yet valid, invalidated by condition notBefore");
					LOG.error("Authentication failure");
					return validateResult;
				}
				if (validTill != null
						&& (validTill.isBeforeNow() || validTill.isEqualNow())) {
					LOG.error("Assertion is no longer valid, invalidated by condition notOnOrAfter");
					LOG.error("Authentication failure");
					validateResult.tokenExpired = true;
					return validateResult;
				}
			}
			
			// Get session index and save it on the session for logout use
			String sessionIndex = null;
			List<AuthnStatement> authnStatement = assertion.getAuthnStatements();
			if (authnStatement != null && !authnStatement.isEmpty()) {
				sessionIndex = authnStatement.get(0).getSessionIndex();
			}
			if (sessionIndex != null) {
				// Save the session index in a cookie rather than http session variable, 
				// so we can still retrieve it when building the SAML logout request 
				// even when the http session timed out and is destroyed.
				Cookie sessionIndexCookie = new Cookie("SAMLSessionIndex", sessionIndex);
                ESAPI.httpUtilities().addCookie(httpResponse, sessionIndexCookie);
			} else {
				LOG.error("Failed to get the session index from the SAML assertion");
				return validateResult;
			}

			int success = 0;
			Subject subject = assertion.getSubject();
			if (subject == null) {
				LOG.error("Assertion subject cannot be null");
				LOG.error("Authentication failure");
				return validateResult;
			}
			try {
				String nameID = subject.getNameID().getValue();
				LOG.debug("The user name in the SAML response is: " + nameID);
				this.setAuthLogin(httpRequest, httpResponse, nameID);
				
				// Save the name ID in a cookie rather than http session variable, 
				// so we can still retrieve it when building the SAML logout request 
				// even when the http session timed out and is destroyed.
				Cookie nameIDCookie = new Cookie("SAMLNameID", nameID);
                HTTPUtilities httpUtilities = ESAPI.httpUtilities();
                httpUtilities.addCookie(httpResponse, nameIDCookie);

			} catch (Exception e) {
				LOG.error("Problem retrieving NameID from Assertion's subject");
				LOG.error("Authentication failure");
				return validateResult;
			}
			// checking subject confirmation's 
			for (SubjectConfirmation confirmation : subject
					.getSubjectConfirmations()) {
				if (SubjectConfirmation.METHOD_BEARER.equals(confirmation
						.getMethod())) {
					SubjectConfirmationData data = confirmation
							.getSubjectConfirmationData();

					if (data == null) {
						LOG.error("Bearer SubjectConfirmation invalidated by missing confirmation data");
						continue;
					}
					if (data.getNotBefore() != null) {
						LOG.error("Bearer SubjectConfirmation invalidated by not before which is forbidden");
						continue;
					}
					DateTime expiry = data.getNotOnOrAfter();
					if (expiry == null) {
						LOG.error("Bearer SubjectConfirmation invalidated by missing notOnOrAfter");
						continue;
					}
					if (expiry.isBeforeNow() || expiry.isEqualNow()) {
						LOG.error("Bearer SubjectConfirmation invalidated by notOnOrAfter");
						continue;
					}
					success = 1;
					break;
				}
			}
			if (success == 0) {
				LOG.error("Not able to validate subject confirmation");
				LOG.error("Authentication failure");
				return validateResult;
			}
			LOG.debug("Authentication success");
			validateResult.isValid = true;
			return validateResult;
		} catch (Exception e) {
			LOG.error("Authentication failure");
			LOG.error("Reason: " + e.getMessage());
			return validateResult;
		} 
	}
	
    /**
     * Validate the SAML logout response
     *
     * @return true if it's valid, false otherwise  
     **/
	private boolean validateSAMLLogoutResponse(LogoutResponse samlresponse) {		
		try {			
			LOG.debug("Validating SAML logout response");
			
			// checking the status of response
			String statusCode = samlresponse.getStatus().getStatusCode()
					.getValue();
			LOG.debug("Logout Response status: " + statusCode);
			if (!statusCode.equals(StatusCode.SUCCESS_URI)) {
				StatusMessage statusMessage = samlresponse.getStatus().getStatusMessage();
	            LOG.error("Status code is not success");
				if (statusMessage != null) {
					String statusMessageText = null;
		            statusMessageText = statusMessage.getMessage();
	                LOG.error("Reason: " + statusMessageText);
	            }
				LOG.error("SAML logout failure");
				return false;
			}

			// validating the signature
			Signature signature = samlresponse.getSignature();
			if (signature == null) {
				LOG.error("Problem  retrieving signature from the provided SAML response.");
				LOG.error("Authentication failure");
				return false;
			}

			boolean validSignature = this.validateSAMLResponseSignature(signature);
			if (!validSignature) {
				return false;
			}

			LOG.debug("SAML logout successful");
			return true;
		} catch (Exception e) {
			LOG.error("SAML logout failure");
			LOG.error("Reason: " + e.getMessage());
			return false;
		} 
	}
	
	/**
	 * Generate the service provider metadata.xml file as a string
	 * @return String with the metadata.xml content
	 */
	private String getServiceProviderMetadataXML() {
		String serviceProviderMetadataXML = null;
		
		// Specify the relying party identifier
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory(); 
        EntityDescriptor spEntityDescriptor = (EntityDescriptor)builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME); 
		spEntityDescriptor.setEntityID(m_issuer);
		
		// Specify that authentication request will be signed by service provider.  
		// Service provider doesn't require individual assertion to be signed by the IdP as long as
		// the whole SAML response is signed by the IdP.
		SPSSODescriptor spSSODescriptor = (SPSSODescriptor)builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME).buildObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME); 
		spSSODescriptor.setWantAssertionsSigned(false); 
		spSSODescriptor.setAuthnRequestsSigned(true);


		X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		keyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		 
		 
       if (!m_signature_initialized) {
        	m_signature = getServiceProviderSignature();
        	m_signature_initialized = true;
        } 
	       
// Generating key info. The element will contain the public key. The key is used to by the IDP to encrypt data
// Currently we don't do encryption.
//		try {
//			KeyDescriptor encKeyDescriptor = (KeyDescriptor)builderFactory.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME).buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME); 		 
//			encKeyDescriptor.setUse(UsageType.ENCRYPTION); //Set usage
//			encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(m_serviceProviderCredential));			
//			spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);
//		} catch (SecurityException e) {
//			LOG.error(e.getMessage(), e);
//		} catch (org.opensaml.xml.security.SecurityException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		 
		// Generating key info. The element will contain the public key. The key is used to by the IDP to verify signatures
		try 
		{
			KeyDescriptor signKeyDescriptor = (KeyDescriptor)builderFactory.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME).buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME); 		 
			signKeyDescriptor.setUse(UsageType.SIGNING);  //Set usage
			signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(m_serviceProviderCredential));
			spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);
		}
		catch (SecurityException e)
		{
			LOG.error(e.getMessage(), e);
		} 
		catch (org.opensaml.xml.security.SecurityException e) 
		{
	        LOG.error(e.getMessage(), e);
		}
 		
		// Specify the D2 URL where the SAML assertion will be posted back to
		AssertionConsumerService assertionConsumerService = (AssertionConsumerService)builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME).buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME); 		 
		assertionConsumerService.setIndex(0);
		assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		assertionConsumerService.setLocation(m_assertionConsumerServiceUrl);
		
		spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

		// Specify the D2 URL where the SAML assertion will be posted back to
		SingleLogoutService singleLogutService = (SingleLogoutService)builderFactory.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME).buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME); 		 
		singleLogutService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		singleLogutService.setLocation(m_logoutResponseEndpointUrl);
		spSSODescriptor.getSingleLogoutServices().add(singleLogutService);
		
		// set SAML as supported protocol
		spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);
		 
		// Generate the metadata.xml
		DocumentBuilder builder;
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		try 
		{
			builder = factory.newDocumentBuilder();

			Document document = builder.newDocument();
			Marshaller out = Configuration.getMarshallerFactory().getMarshaller(spEntityDescriptor);
			out.marshall(spEntityDescriptor, document);

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            // Added because of Fortify Scan mitigation: 'XML External Entity Injection'
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            /*
             * Commenting due to following exception. Please refer to DTWO-59781 for further details
             * java.lang.IllegalArgumentException: Unknown configuration option http://javax.xml.XMLConstants/property/accessExternalDTD
             */
            //transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            //transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = transformerFactory.newTransformer();

			StringWriter stringWriter = new StringWriter();
			StreamResult streamResult = new StreamResult(stringWriter);
			DOMSource source = new DOMSource(document);
			transformer.transform(source, streamResult);
			stringWriter.close();
			serviceProviderMetadataXML = stringWriter.toString();
		} catch (ParserConfigurationException e) {
	        LOG.error(e.getMessage(), e);
		} catch (MarshallingException e) {
	        LOG.error(e.getMessage(), e);
		} catch (TransformerConfigurationException e) {
	        LOG.error(e.getMessage(), e);
		} catch (TransformerFactoryConfigurationError e) {
	        LOG.error(e.getMessage(), e);
		} catch (TransformerException e) {
	        LOG.error(e.getMessage(), e);
		} catch (IOException e) {
	        LOG.error(e.getMessage(), e);
		}

		return serviceProviderMetadataXML;
	}
	
	class SamlEntityResolver implements EntityResolver
	{
		@Override
		public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
			
			LOG.debug(" EntityResolver requested for systemId : {} ", systemId);
			
			InputSource inputSource = null;
			if(systemId.contains("saml-schema-assertion-2.0.xsd"))
			{
				InputStream assertionSchemaStream = SamlEntityResolver.class.getClassLoader().getResourceAsStream("schema" + File.separator + "saml-schema-assertion-2.0.xsd");
				inputSource = new InputSource(assertionSchemaStream);
			}
			else if(systemId.contains("xmldsig-core-schema.xsd")) 
			{
				InputStream xmldSigStream = SamlEntityResolver.class.getClassLoader().getResourceAsStream("schema" + File.separator + "xmldsig-core-schema.xsd");
				inputSource = new InputSource(xmldSigStream);
			}
			else if(systemId.contains("xenc-schema.xsd")) 
			{
				InputStream xmlEncStream = SamlEntityResolver.class.getClassLoader().getResourceAsStream("schema" + File.separator + "xenc-schema.xsd");
				inputSource = new InputSource(xmlEncStream);
			}
			else if(systemId.contains("http://www.w3.org/2001/XMLSchema.dtd")) 
			{
				InputStream xmldSchStream = SamlEntityResolver.class.getClassLoader().getResourceAsStream("schema" + File.separator + "XMLSchema.dtd");
				inputSource = new InputSource(xmldSchStream);
			}
			else if(systemId.contains("datatypes.dtd")) 
			{
				InputStream xmldataTypesStream = SamlEntityResolver.class.getClassLoader().getResourceAsStream("schema" + File.separator + "datatypes.dtd");
				inputSource = new InputSource(xmldataTypesStream);
			}
			
			if(inputSource != null)
			{
				LOG.debug( " Found xsd for SystemId : {}", systemId);
			}
			else
			{
				LOG.debug( " No schema file found for SystemId : {}",  systemId);
			}	
			return inputSource;
		}
	}
	
	class SamlErrorHandler implements ErrorHandler
	{
		private boolean isErrorOccured = false;
		
		public boolean isErrorOccured() {
			return isErrorOccured;
		}

		public void setErrorOccured(boolean isErrorOccured) {
			this.isErrorOccured = isErrorOccured;
		}

		@Override
		public void error(SAXParseException saxParseException) throws SAXException {
			isErrorOccured = true;
			LOG.error(" Error has occured while validating SAML Response : {}", saxParseException.getMessage());
		}

		@Override
		public void fatalError(SAXParseException saxParseException) throws SAXException {
			isErrorOccured = true;
			LOG.error("Fatal Error has occured while validating SAML Response : {}", saxParseException.getMessage());
		}

		@Override
		public void warning(SAXParseException saxParseException) throws SAXException {
			LOG.warn("Warning reported while validating SAML Response " + saxParseException.getMessage());
		}
	}
}
