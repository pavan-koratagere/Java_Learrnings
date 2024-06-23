import com.emc.documentum.kerberos.utility.KerberosUtility;
import com.emc.documentum.kerberos.utility.AcceptResult;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import java.security.PrivilegedAction;

/**
 * 
 * @author pkoratag
 *
 */
public class KerbConstrainedDelegation
{
    public static void main (String[] args)
    {
            GSSCredential tgt=null;
            try
            {
                LoginContext loginCtx = new LoginContext("CS-xyz");
                loginCtx.login();
                tgt = (GSSCredential) Subject.doAs(loginCtx.getSubject(), new PrivilegedAction()
			                        {
			                            public Object run ()
			                            {
			                                try
			                                {
			                                    GSSManager manager = com.dstc.security.kerberos.gssapi.GSSManager.getAnonymousInstance();
			                                    GSSName clientName = manager.createName("krb2@SRIHARI.LOCAL", GSSName.NT_USER_NAME);
			                                    System.out.println("before getting credentials");//1.2.840.113554.1.2.2
			                                    return manager.createCredential(clientName, GSSCredential.DEFAULT_LIFETIME, new Oid("1.2.840.113554.1.2.2"), GSSCredential.INITIATE_ONLY);
			                                }
			                                catch (GSSException e)
			                                {
			                                    throw new RuntimeException(e.getMessage(), e);
			                                }
			
			                            }
			
			                        });
                
                String target_st= KerberosUtility.delegate("HTTP/ep7ah.srihari.local", tgt); //App server SPN
                System.out.println("hurray received ST for HTTP/ep7ah.srihari.local");
                
                AcceptResult acceptResult =  KerberosUtility.accept("HTTP/ep7ah.srihari.local", target_st); //App server 
                GSSCredential gscred=acceptResult.getDelegatedCred();
                
                String target_st2 = KerberosUtility.delegate("CS/ep7repo", gscred); //CS Server
                System.out.println("hurray received ST for CS/ep7repo");
                
                AcceptResult acceptResult_1 =  KerberosUtility.accept("CS/ep7repo", target_st2); //CS Server
                GSSCredential gssCredentialOfCS = acceptResult_1.getDelegatedCred();
                System.out.println("hurray received credentials for CS/ep7repo ----------- " + gssCredentialOfCS.getName());
                
                

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
    
    static
    {
        System.setProperty("jcsi.kerberos.debug", "true");
        System.setProperty("jcsi.kerberos.nameservers", "10.194.47.57");
        System.setProperty("java.security.auth.login.config","c:\\pavan\\sso\\krb5Login.conf");
        System.setProperty("constrained.delegate.enable","true");

    }
}
