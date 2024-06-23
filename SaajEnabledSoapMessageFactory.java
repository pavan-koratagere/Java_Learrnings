package com.emc.d2fs.soap;


import jakarta.xml.soap.SOAPMessage;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPException;

import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;

public class SaajEnabledSoapMessageFactory extends SaajSoapMessageFactory {

    private MessageFactory soapFactory = null;
    
    public SaajEnabledSoapMessageFactory() {
    	try {
			soapFactory=MessageFactory.newInstance();
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
	@Override
	public SaajSoapMessage createWebServiceMessage()
    {
		SOAPMessage soapMessage = null;
		try {
			soapMessage = soapFactory.createMessage();
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return new SaajSoapMessage(soapMessage){
			@Override
			public boolean convertToXopPackage() {
		        return true;
		    }
		};
     
    }
    
//    @Override
//	public void setSoapVersion(SoapVersion version) {
//    	if (SaajUtils.getSaajVersion() >= SaajUtils.SAAJ_13) {
//			if (SoapVersion.SOAP_11 == version) {
//				soapFactory = SOAPConstants.SOAP_1_1_PROTOCOL;
//			} else if (SoapVersion.SOAP_12 == version) {
//				soapFactory = SOAPConstants.SOAP_1_2_PROTOCOL;
//			} else {
//				throw new IllegalArgumentException(
//						"Invalid version [" + version + "]. Expected the SOAP_11 or SOAP_12 constant");
//			}
//		} else if (SoapVersion.SOAP_11 != version) {
//			throw new IllegalArgumentException("SAAJ 1.1 and 1.2 only support SOAP 1.1");
//		}    }
}
