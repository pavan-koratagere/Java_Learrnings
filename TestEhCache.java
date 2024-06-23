import java.net.URL;
import java.util.Scanner;

import com.emc.common.java.cache.D2CacheManager;
import com.emc.common.java.cache.D2CacheManagerImpl;
import com.emc.common.java.utils.ClassUtil;
import com.emc.common.java.utils.D2CommonBofServicesUtil;
import com.emc.common.java.xml.XmlDocument;
import com.emc.common.java.xml.XmlUtil;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Status;
import net.sf.ehcache.event.CacheManagerEventListener;

public class TestEhCache {

	static D2CacheManager d2CacheManager;
	
	public static void main(String[] args) {
		//Test cacheMananager shutdown and restrat events
		String option = null;
		do
		{
			System.out.println(" 1. Start Ehcahe Manager ");
			System.out.println(" 2. Shutdown Ehcahe Manager ");
			System.out.println(" 3. Restart Ehcahe Manager ");
			System.out.println(" 4. Check Ehcahe status ");
			System.out.println(" 5. Exit ");
			System.out.println("--- Enter the option -1/2/3 --------- ");
			option = new Scanner(System.in).nextLine();
			
			switch (option) {
			case "1" : startCache();
						break;
			case "2" : stopCache();
						break;
			case "3" : restartCache();
						break;
			case "4":  System.out.println("Enter cache name which u want to access ");
						String cacheName = new Scanner(System.in).nextLine();
						isCacheEnabled(cacheName);
						break;
			case "5" : System.out.println(" Exiting ");
						System.exit(0);
						break;
			default:break;
			}
		}
		while(true);
	}

	private static void isCacheEnabled(String cacheName) {

		try
		{
			System.out.println(" -- Verifying given Cache : " + cacheName + " is enabled or not");
			Ehcache ehcache = d2CacheManager.getCache(cacheName);
			System.out.println(" Cache : " + cacheName + " status : " + ehcache.getStatus().toString());
		}
		catch (Exception e) 
		{
			e.printStackTrace();
		}
	}

	static void startCache()
	{
		XmlDocument ehCacheConfig = getEhCaheConfig();		
		System.out.println("----- Begin Initializing D2 CacheManager ------");
		d2CacheManager = new D2CacheManagerImpl();
		d2CacheManager.initConfigurationOnce(ehCacheConfig);
		System.out.println("-----End Initializing D2 CacheManager---------");
		
		CacheManager cacheManager = d2CacheManager.getCacheManager();
		cacheManager.getCacheManagerEventListenerRegistry().registerListener(new CacheManagerEventListener(){

			@Override
			public void init() throws CacheException {
				System.out.println(" CacheManager got inititalized ");
			}

			@Override
			public Status getStatus() {
				System.out.println(" CacheManager getStatus called");
				return null;
			}

			@Override
			public void dispose() throws CacheException {
				System.out.println(" CacheManager dispose called");
				
			}

			@Override
			public void notifyCacheAdded(String cacheName) {
				System.out.println(" CacheManager notifyCacheAdded called for cache : " + cacheName);
			}

			@Override
			public void notifyCacheRemoved(String cacheName) {
				System.out.println(" CacheManager notifyCacheRemoved called for cache : " + cacheName);
			}
		});
		
		System.out.println("cacheManager status :" + cacheManager.getStatus().toString());
		System.out.println(" cacheManager started ------- :");
	}
	
	static XmlDocument getEhCaheConfig()
	{
		XmlDocument xmlConfig1 = null;
    	try
        {
            // initialize the cache manager with the default resource
            String resource = "d2-cache.xml";
            URL url = D2CacheManager.class.getResource(resource);
            System.out.println("Default Url for EhCache config " + url.getFile());
            xmlConfig1 = XmlUtil.loadFromURL(url);
        }
        catch (Exception ce)
        {
            ce.printStackTrace();
        }
    	return xmlConfig1;
	}
	
	static void stopCache()
	{
		System.out.println("----- shutting down cacheManager started ------- :");
		System.out.println(" CacheManager status before shutdown ---- " + d2CacheManager.getCacheManager().getStatus().toString());
		d2CacheManager.getCacheManager().shutdown();
		System.out.println(" CacheManager status after shutdown ---- " + d2CacheManager.getCacheManager().getStatus().toString());
	}
	
	private static void restartCache() {
		System.out.println("---------- Restart cacheManager -----------");
		XmlDocument ehCacheConfig = getEhCaheConfig();				
		CacheManager cacheManager = d2CacheManager.getCacheManager().create(ehCacheConfig.getInputStream());
		System.out.println(" CacheManager status after Restart ---- " + cacheManager.getStatus().toString());
	}
}
