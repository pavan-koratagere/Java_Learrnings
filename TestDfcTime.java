package com.opentext.d2.time;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import com.documentum.fc.client.DfClient;
import com.documentum.fc.client.IDfClient;
import com.documentum.fc.client.IDfPersistentObject;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.common.DfId;
import com.documentum.fc.common.DfLoginInfo;
import com.documentum.fc.common.DfTime;
import com.documentum.fc.common.IDfTime;
import com.documentum.fc.common.IDfValue;


public class TestDfcTime {

	private static final String DOC_BASE = "d2repo";

	public static void main(String[] args)throws Exception {

		String[] timeZoneArray =TimeZone.getAvailableIDs();
		System.out.println(Arrays.toString(timeZoneArray));
		
		IDfClient dfcClient = DfClient.getInstance();
		IDfSessionManager sessionManager = dfcClient.newSessionManager();
		sessionManager.setIdentity(DOC_BASE, new DfLoginInfo("dmadmin", "password"));
		
		
		String dfcTimeZone = sessionManager.getConfig().getTimeZone();
		System.out.println(" before dfc client TimeZone : " + dfcTimeZone);
		
		
		sessionManager.getConfig().setTimeZone("UTC");
		System.out.println(" dfc client TimeZone After changing into UTC " + sessionManager.getConfig().getTimeZone());
	
		
		
		IDfSession session = sessionManager.getSession(DOC_BASE);
		
		System.out.println(" dfc session  client TimeZone :  " + session.getSessionManager().getConfig().getTimeZone());
		System.out.println(" dfc session  client  Locale :  " + session.getSessionManager().getConfig().getLocale());
		
		//Session mele check madu
		//session.getSessionManager().getConfig().setTimeZone("Asia/Calcutta");
		
		//Asia/Qyzylorda
		
		IDfPersistentObject m_persistentObject = session.getObject(new DfId("090015fa80008aa9"));
		IDfValue value = m_persistentObject.getValue("a_last_review_date");
		
		IDfTime timeOld = value.asTime();
		System.out.println(" a_last_review_date timeOld value  : " + timeOld.toString());
		
		//Now parse Date UI value
		String newDateString = "26/05/2020 12:30:00";
		
		SimpleDateFormat simpleDateInputFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.ENGLISH);
    	simpleDateInputFormat.setTimeZone(TimeZone.getTimeZone("Asia/Qyzylorda"));
    	
    	DfTime timeNew =  new DfTime(newDateString, simpleDateInputFormat);
		System.out.println(" a_last_review_date timeNew value  : " + timeNew.toString());
		
		 if ((timeNew.getYear() == timeOld.getYear()) && (timeNew.getMonth() == timeOld.getMonth())
         		&& (timeNew.getDay() == timeOld.getDay())
         		&& (timeNew.getHour() == timeOld.getHour())
         		&& (timeNew.getMinutes() == timeOld.getMinutes())
     			&& (timeNew.getSeconds() == timeOld.getSeconds()))
			 System.out.println("TimeZoneIssue : attribute {} timeOld and timeNew are same so skiping save on object");
		 else
			 System.out.println("TimeZoneIssue : attribute {} timeOld and timeNew are diffrent");
		/*IDfTime time = value.asTime();
		Date date = time.getDate();
		
		SimpleDateFormat simpleDateInputFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.ENGLISH);
    	simpleDateInputFormat.setTimeZone(TimeZone.getTimeZone("Asia/Qyzylorda"));
		
    	String dateFormatedValue = simpleDateInputFormat.format(date);
    	System.out.println("dd/MM/yyyy HH:mm:ss : value with timezone : Asia/Qyzylorda : " + dateFormatedValue);*/
		
		if(session.isConnected())
		{
			session.getSessionManager().release(session);
		}
		
		
		
	}

}
