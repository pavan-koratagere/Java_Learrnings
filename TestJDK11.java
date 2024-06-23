package test_compiler;

import java.lang.reflect.Field;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;

public class TestJDK11 {

	public static void main(String[] args) {

		try 
		{
			DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			Document document = documentBuilder.newDocument();
			document.createElement("data");
			System.out.println(" document created " + document.getLocalName());
			
			System.out.println(" TestJDK11 ClassLoader " + TestJDK11.class.getClassLoader().getName());
			try {
				Class javaBeanClass = Class.forName("test_compiler.JavaBean");
				Field[] fields = javaBeanClass.getDeclaredFields();
				for(Field field : fields)
				{
					System.out.println( field.getName() );
				}	
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		catch (ParserConfigurationException e) 
		{
			e.printStackTrace();
		}
	}

}
