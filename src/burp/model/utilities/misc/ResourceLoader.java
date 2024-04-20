package burp.model.utilities.misc;

import java.io.*;
import java.util.Properties;
import java.util.stream.Collectors;

public class ResourceLoader {

public static String loadFile(String fileName) throws Exception {
  InputStream inputStream;
  String      fileContents;
  
  try {
    // load given resource as inputStream
    inputStream = ResourceLoader.class.getClassLoader().getResourceAsStream(fileName);
    
    if (inputStream != null) {
      // Read the content of the resource
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      fileContents = reader.lines().collect(Collectors.joining(System.lineSeparator()));
      
    }
    else {
      throw new FileNotFoundException("Resource not found: " + fileName);
    }
  }
  catch (Exception e) {
    throw new Exception("Failed to load resource \"" + fileName + "\": " + e);
  }
  
  inputStream.close();
  return fileContents;
}

public static Properties loadPropertyFile(String fileName) throws IOException {
  Properties defaultProps = new Properties();
  
  // Load default values from properties file
  InputStream input = ResourceLoader.class.getClassLoader().getResourceAsStream(fileName);
  defaultProps.load(input);
  return defaultProps;
}
}
