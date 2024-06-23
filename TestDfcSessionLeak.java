package test_compiler;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import com.documentum.fc.client.DfClient;
import com.documentum.fc.client.DfPersistentObject;
import com.documentum.fc.client.DfServiceException;
import com.documentum.fc.client.IDfClient;
import com.documentum.fc.client.IDfPersistentObject;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.client.impl.connection.docbase.DocbaseConnectionManager;
import com.documentum.fc.client.impl.session.ISession;
import com.documentum.fc.client.impl.session.ISessionRegistry;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.DfLoginInfo;
import com.documentum.fc.common.DfPreferences;
import com.documentum.fc.common.IDfLoginInfo;
import com.documentum.fc.impl.RuntimeContext;

public class TestDfcSessionLeak {

	static final String DOC_BASE = "testenv";
	static List<IDfSession> sessionList = new ArrayList<IDfSession>();
	static List<IDfPersistentObject> objectCache = new ArrayList<IDfPersistentObject>();
	
	public static void main(String[] args) throws DfException, Exception {
		System.setOut(new MyPrintStream1(System.out));
		System.out.println("dfc.session.pool.mode : " + DfPreferences.getInstance().getSessionPoolMode());
		System.out.println(" dfc.session.global_pool_enabled : " +DfPreferences.getInstance().isGlobalSessionPoolEnabled());
		System.out.println(" isD7SessionPoolingUsed : " + DfPreferences.getInstance().isD7SessionPoolingUsed());
	
		IDfClient dfcClient = DfClient.getInstance();
		IDfSessionManager sessionManager = dfcClient.newSessionManager();
		sessionManager.setIdentity(DOC_BASE, new DfLoginInfo("user1", "password"));
		IDfSession session = sessionManager.getSession(DOC_BASE);
		System.out.println(" Session ID : " + session.getSessionId() + " Connection ID " + session.getConnectionConfig().getString("connection_id") );
		
	}

}
class MyPrintStream1 extends PrintStream
{
	public MyPrintStream1(File file) throws FileNotFoundException {
		super(file);
	}
	
	public MyPrintStream1(OutputStream out) {
		super(out);
	}

	@Override
	  public void println(String x) {
		  //Add the Date
		  SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		  String outPut = simpleDateFormat.format(new Date()) + " ---- " + x;
		  super.println(outPut);
	    }
}