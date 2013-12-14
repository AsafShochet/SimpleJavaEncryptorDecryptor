/* Imports */
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import java.io.File;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
 
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
 
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyStore;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
/**
 * @author a
 *
 */
public class cryptoClass {
	
	/* Encrypts and Signs a clear text file to be send between a sender and a receiver, in the following way:
	 * 1. Generates a symmetric key SK
	 * 2. Uses SK to encrypt the clear text file
	 * 3. Reads receiver's public key, and encrypts SK with it (Asymetric encryption)
	 * 4. Signs the clear text file using sender's private key
	 * 5. Generates a cipher configurations XML file (includes digital signature), to be sent to the receiver with the encrypted file
	 */ 
	static public boolean EncryptAndSignAFile(HashMap<String,String> senderConfigurations,HashMap<String,String> configurationData,HashMap<String,String> receiverConf) throws Exception
	{
		/* Generate symmetric key for AES-CBC encryption of the file */
		Key sharedKey = (KeyGenerator.getInstance(configurationData.get("encryptionAlgoForKeyGen"))).generateKey(); // generate symetric key
		Cipher encryptor = Cipher.getInstance(configurationData.get("encryptionType"));
		
		byte[] iv = new byte[encryptor.getBlockSize()]; // create IV byte array
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(iv); // generate random iv
		IvParameterSpec ivspec = new IvParameterSpec(iv); // initialize IV
		
		/* Encrypt the file */
		EncryptFile(senderConfigurations.get("fileToEncrypt"),senderConfigurations.get("encryptedTextFile"),encryptor,sharedKey, ivspec);  // Encrypts file with symetric key and writes cipher into encryptedTextFile
	
		/* Save Configurations into configuration file encrypted by public key of the receiver*/
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(senderConfigurations.get("keyStorePath"));
        ks.load(ksStream, senderConfigurations.get("keyStorePass").toCharArray());
        PublicKey receiverPublicKey = ks.getCertificate(senderConfigurations.get("receiverAlias")).getPublicKey(); //receiverPublicKey holds the public key for receiver
     
        Cipher rsaEncryptor = Cipher.getInstance(configurationData.get("encryptionAlgoForSecretKey")); // encryptor for the secret key
        byte[] symetricKeyEncrypted = EncryptText(sharedKey.getEncoded(),rsaEncryptor,receiverPublicKey, null);  // Encrypts the symetric key using public key of the reciever
        
        /* Loads private key from keyStore, needed to decrypt the symmetric key from configuration file */
      	PrivateKey receiverPrivateKey =  (PrivateKey) ks.getKey(receiverConf.get("receiverAlias"), receiverConf.get("receiverKeyPass").toCharArray()); //private key of receiver
      		
      	/* For Testing 
        byte[] decryptedKey = DecryptText(symetricKeyEncrypted, rsaEncryptor, receiverPrivateKey, null);
        
        if (decryptedKey.toString().getBytes() == decryptedKey)
        	System.out.println("Bytes are equal");
        SecretKeySpec sks = new SecretKeySpec(decryptedKey, configurationData.get("encryptionAlgoForKeyGen"));
        if (sks.equals(sharedKey))
        	System.out.println("Equal");
        /* End of testing */
        configurationData.put("symetricKeyEncrypted",Base64.encodeBase64String(symetricKeyEncrypted));
        byte[] ivEncrypted =EncryptText(ivspec.getIV(),rsaEncryptor,receiverPublicKey, null);
        configurationData.put("ivspec",Base64.encodeBase64String(ivEncrypted));
        /* Create configuration XML */ 
      
        /* Calculate digital signature */
        PrivateKey senderPrivateKey = (PrivateKey) ks.getKey(senderConfigurations.get("senderAlias"), senderConfigurations.get("enctyptorKeyPass").toCharArray()); //publicKey holds the public key for sender
        byte[] digitalSignature = CalculateDigitalSignature(senderConfigurations.get("fileToEncrypt"),configurationData.get("digitalSignatureAlgorithm"),senderPrivateKey);
        configurationData.put("digitalSignature",Base64.encodeBase64String(digitalSignature));
      
		if (!CreateCipherConfigurationXML(configurationData, senderConfigurations.get("configurationFile"))) 
		System.out.println("Error creating configuration file.\nAborting...\n");
		return true;
    		
	}
	
	/* Decrypts and validates a signature of an encrypted file that was sent between a sender and a receiver, in the following way:
	 * 1. Uses private key to encrypt a symmetric key from a configuration file.
	 * 2. Uses the symmetric key to decrypt the message sent in a different file
	 * 3. Calculates digital signature over the file, and compares it with the one received in the configuration file.
	 * 4. If the signatures match - returns true, else - returns false
	 * */ 
	static public boolean DecryptFileAndValidateSignature(HashMap<String,String> receiverConfigurations) throws Exception
	{
		/* Load data from keyStore .jks file */
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(receiverConfigurations.get("keyStorePath"));
        ks.load(ksStream, receiverConfigurations.get("keyStorePass").toCharArray());
       
        /* Loads private key from keyStore, needed to decrypt the symmetric key from configuration file */
		PrivateKey receiverPrivateKey =  (PrivateKey) ks.getKey(receiverConfigurations.get("receiverAlias"), receiverConfigurations.get("receiverKeyPass").toCharArray()); //private key of receiver
		
		/* Load data received by the cipher configurations XML sent by sender */
		HashMap<String,String> cipherConfigurations = ReadConfigurationXML(receiverConfigurations.get("configurationFile"));
		if (cipherConfigurations == null)
		{
			System.out.println("Error reading cipher configurations XML.\nAborting...");
		}
		
		/* Initialize the encryptor */
		Cipher encryptor = Cipher.getInstance(cipherConfigurations.get("encryptionType"));
		
        /* Get data from cipher configurations XML*/
		byte[] symetricKeyEncrypted =Base64.decodeBase64(cipherConfigurations.get("symetricKeyEncrypted"));
		/* Initialize the symmetric key encryptor */
		Cipher rsaEncryptor = Cipher.getInstance(cipherConfigurations.get("encryptionAlgoForSecretKey")); // encryptor for the secret key
	    byte[] symetricKeyDecrypted = DecryptText(symetricKeyEncrypted,rsaEncryptor,receiverPrivateKey, null);
        
		byte[] ivConfig =Base64.decodeBase64(cipherConfigurations.get("ivspec"));
		byte[] iv = DecryptText(ivConfig, rsaEncryptor, receiverPrivateKey, null);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		byte[] digitalSignature = Base64.decodeBase64(cipherConfigurations.get("digitalSignature"));
		
		Key symmetricKeyAfterDecription =  new SecretKeySpec(symetricKeyDecrypted, cipherConfigurations.get("encryptionAlgoForKeyGen")); //build a new secret key from text
        
        
        boolean decryptionOK = DecryptFileAndValidateSignature(receiverConfigurations.get("keyStorePath"),receiverConfigurations.get("keyStorePass"),receiverConfigurations.get("senderAlias"),receiverConfigurations.get("senderKeyPass"),receiverConfigurations.get("decryptedTextFile"), receiverConfigurations.get("encryptedTextFile"),encryptor,symmetricKeyAfterDecription,ivSpec,cipherConfigurations.get("digitalSignatureAlgorithm"),digitalSignature);
        if (!decryptionOK)
        {
        	System.out.println("Error decrypting text or validating digital signature.\nAborting...");
        	return false;
        }
        else
        {
        	System.out.println("Decrypting of text was OK.\nDigital signature successfully validated.");
        	return true;
        }
      }
	
	static public void main(String args[]) throws Exception 
	{
	
		/* Constants */
		/* File paths*/
      	/* Passwords */
		
		
		/* Configurations that are known to the sender */
		HashMap<String,String> senderConfigurations = new HashMap<>();
		senderConfigurations.put("fileToEncrypt", "c:\\test\\crypto\\fileToEncrypt.txt");
		senderConfigurations.put("encryptedTextFile" ,"c:\\test\\crypto\\encryptedTextFile.txt");
		senderConfigurations.put("configurationFile","c:\\test\\crypto\\cipherConfigurations.xml");
		senderConfigurations.put("keyStorePath","c:\\test\\crypto\\keystore.jks");
		senderConfigurations.put("keyStorePass","J34QqUf");
		senderConfigurations.put("senderAlias","encryptorKey");
		senderConfigurations.put("enctyptorKeyPass","U8MyK7");
		senderConfigurations.put("receiverAlias","decryptorKey");
		
		/* Configurations that are known to the receiver */
		HashMap<String,String> receiverConfigurations = new HashMap<>();
		receiverConfigurations.put("encryptedTextFile" ,"c:\\test\\crypto\\encryptedTextFile.txt");
		receiverConfigurations.put("configurationFile","c:\\test\\crypto\\cipherConfigurations.xml");
		receiverConfigurations.put("keyStorePass","J34QqUf");
		receiverConfigurations.put("receiverAlias","decryptorKey");
		receiverConfigurations.put("receiverKeyPass","Hu87Ql");
		receiverConfigurations.put("decryptedTextFile","c:\\test\\crypto\\decryptedText.txt");
		receiverConfigurations.put("keyStorePath","c:\\test\\crypto\\keystore.jks");
		receiverConfigurations.put("senderAlias","encryptorKey");
		
		/*Data for configurations XML file*/
		HashMap<String,String> configurationData = new HashMap();
		configurationData.put("encryptionType","AES/CBC/PKCS5PADDING"); // AES algorithm in CBC mode Encryption algorithm
		configurationData.put("encryptionAlgoForKeyGen","AES");
		configurationData.put("encryptionAlgoForSecretKey","RSA/ECB/PKCS1Padding");
		configurationData.put("digitalSignatureAlgorithm","MD5withRSA");
	    
		/* End of Paths and key names */
		
		EncryptAndSignAFile(senderConfigurations,configurationData,receiverConfigurations);
		DecryptFileAndValidateSignature(receiverConfigurations);
		
		}
	
	private static boolean DecryptFileAndValidateSignature(String keyStorePath,String keyStorePass, String senderAlias, String enctyptorKeyPass, String decryptedFile, String encryptedTextFile,Cipher encryptor, Key sharedKey,IvParameterSpec ivspec, String digitalSignatureAlgorithm, byte[] digitalSignature) throws Exception {
		
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(keyStorePath);
        ks.load(ksStream, keyStorePass.toCharArray());
        
		/* Decrypt file into decryptedFile */
        DecryptFile(encryptedTextFile, decryptedFile, encryptor, sharedKey,ivspec);
        
        /* Verify digital signature */
        PublicKey senderPublicKey = ks.getCertificate(senderAlias).getPublicKey(); //publicKey holds the public key for sender
        boolean signatureValidated = ValidateDigitalSignature(decryptedFile,digitalSignatureAlgorithm,senderPublicKey,digitalSignature);
       
        return signatureValidated;
	}

	/* Simulates the process where the receiver is calculating the signature of a message he received
	 * and compares it to the signature sent to him by sender.
	 * Calculates the digital signature over the decrypted file, using the digital signature algorithm in digitalSignatureAlgorithm,
	 * and public key in senderPublicKey.
	 * returns true iff the signatures match.
	 *  */
	
	private static boolean ValidateDigitalSignature(String decryptedFile,
		String digitalSignatureAlgorithm, PublicKey senderPublicKey, byte[] signatureToVerify) throws Exception {
		Signature dsa = Signature.getInstance(digitalSignatureAlgorithm);       /* Initializing the object with the digital signature algorithm */ 
        dsa.initVerify(senderPublicKey); 
        /* Update and sign the data */ 
        FileInputStream fis = new FileInputStream(decryptedFile); 
		byte[] block = new byte[8];
		int i;
		while ((i = fis.read(block)) != -1) { //read all blocks in file
			dsa.update(block); // update digital signature after each block 
		}
		fis.close();
        return dsa.verify(signatureToVerify);
        }
	
	/*
	 * Simulates the process where the sender is signing his own text.
	 * Calculates the digital signature over the fileToSign, using the digital signature algorithm in digitalSignatureAlgorithm,
	 * and private key in senderPrivateKey.
	 *  */
	private static byte[] CalculateDigitalSignature(String fileToSign,
			String digitalSignatureAlgorithm, PrivateKey senderPrivateKey)   throws Exception{
		
			Signature dsa = Signature.getInstance(digitalSignatureAlgorithm);       /* Initializing the object with the digital signature algorithm */
		    dsa.initSign(senderPrivateKey); 
	        /* Update and sign the data */ 
	        FileInputStream fis = new FileInputStream(fileToSign); 
			byte[] block = new byte[8];
			int i;
			while ((i = fis.read(block)) != -1) { //read all blocks in file
				dsa.update(block); // update digital signature after each block 
			}
	        byte[] sig = dsa.sign();
	        fis.close();
	        return sig;
	}

	/* Reads a file and encrypts it using a Cipher object (encryptor).
	 * The encrypted file will be written to outputFile.
	 * Encryption process contains also Base64 encoding of the file.
	 */
	private static void EncryptFile(String inputFile,String outputFile, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		assert (CreateFileIfNecessery(outputFile) == true); //creates output file if necessery
		FileInputStream fis = new FileInputStream(inputFile); 
		FileOutputStream fos = new FileOutputStream(outputFile);
		Base64OutputStream b64os = new Base64OutputStream(fos);
		CipherOutputStream cos = new CipherOutputStream(b64os, encryptor);
		
		encryptor.init(Cipher.ENCRYPT_MODE, key, ivspec);  // initialize cipher in ecryption mode
		byte[] block = new byte[8];
		int i;
		
		while ((i = fis.read(block)) != -1) { //read all blocks in file
			{
			System.out.println(Base64.decodeBase64(block));
			cos.write(block,0, i); // write each block encrypted to the output file converted to base64
			System.out.println(block);
			}
		}
		cos.close(); // close output file
		b64os.close();
		fis.close();
		fos.close();
		System.out.println("Output file: "+outputFile);
		
	}
		
	
	/* Reads a file and encrypts it using a Cipher object (encryptor).
	 * The encrypted file will be written to outputFile.
	 * Encryption process contains also Base64 encoding of the text.
	 */
	public static byte[] EncryptText(byte[] text, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		InputStream is = new ByteArrayInputStream(text);
		OutputStream os = new ByteArrayOutputStream();
		Base64OutputStream b64os = new Base64OutputStream(os);
		
		CipherOutputStream cos = new CipherOutputStream(b64os, encryptor);
	
		encryptor.init(Cipher.ENCRYPT_MODE, key, ivspec);  // initialize cipher in ecryption mode
		byte[] block = new byte[8];
		int i;
		while ((i = is.read(block)) != -1) { //read all blocks in file
			{
				cos.write(block,0, i); // write each block encrypted to the output file converted to base64
			}
		}
		cos.close(); // close output file
		os.close();
		return ((ByteArrayOutputStream) os).toByteArray();
	}
	
	/* Reads an encrypted text and decrypts it using a Cipher object (encryptor).
	 * The decrypted text will be the returned value.
	 * Decryption process contains also Base64 encoding of the text.
	 */
	public static byte[] DecryptText(byte[] text, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		OutputStream os = new ByteArrayOutputStream();
		InputStream is = new ByteArrayInputStream(text);
		Base64InputStream b64is = new Base64InputStream(is);
		CipherInputStream cis = new CipherInputStream(b64is, encryptor);
		encryptor.init(Cipher.DECRYPT_MODE, key, ivspec); //initilize cipher in decryption mode with IV
		byte[] block = new byte[8];
		int i;	
		while ((i = cis.read(block)) != -1) { //read all blocks in file
			{
				os.write(block,0, i); // write each block encrypted to the output file
			}
		}
		b64is.close();
		os.close(); // close output file
		is.close(); // close input file
		cis.close();
		return ((ByteArrayOutputStream) os).toByteArray();
	}
		
	/* Reads an encrypted text file and decrypts it using a Cipher object (encryptor).
	 * The decrypted file will be the returned value.
	 * Decryption process contains also Base64 encoding of the text.
	 */
	private static void DecryptFile(String inputFile,String outputFile, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		assert (CreateFileIfNecessery(outputFile) == true); //creates output file if necessery
		FileInputStream fis = new FileInputStream(inputFile);
		Base64InputStream b64os = new Base64InputStream(fis);
		CipherInputStream cis = new CipherInputStream(b64os, encryptor);
		
		FileOutputStream fos = new FileOutputStream(outputFile);
		
		encryptor.init(Cipher.DECRYPT_MODE, key, ivspec); //initilize cipher in decryption mode with IV
				
		byte[] block = new byte[8];
		int i;
		while ((i = cis.read(block)) != -1) { //read all blocks in file
			{
				fos.write(block,0,i); // write each block encrypted to the output file
			}
		}
		b64os.close();
		fos.close(); // close output file
		cis.close(); // close input file
	}
		
	
	/* 
	 * Creats file and its paths if not exist.
	 * Example: path = c:\\test\\test1\\foo.txt
	 * Method will check if this path and file exists, if not - will create full hierarchy.
	 */
	private static boolean CreateFileIfNecessery(String path) throws Exception
	{
		File f = new File(path);
		if (!f.mkdirs()) return false; //creates the directories for the file
		if (!f.createNewFile()) return false; // creates the output file
		return true;
	}

	public static boolean CreateCipherConfigurationXML(HashMap<String,String> dataToWrite, String path) throws Exception
	{
	//	assert (CreateFileIfNecessery(path) == true);
	
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
 
		// root elements
		Document doc = docBuilder.newDocument();
		Element rootElement = doc.createElement("CipherConfigurations");
		doc.appendChild(rootElement);
		for (String key : dataToWrite.keySet()) //add children - encryption\signature attributes
		{
			Element elem = doc.createElement(key);
			elem.setTextContent(dataToWrite.get(key));
			rootElement.appendChild(elem);
		}
		
		// write the content into xml file
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(new File(path));
 		transformer.transform(source, result);
 
		
		return true;
	}
	
	/*
	 * Reads the configuration XML from file in 'path'.
	 * Retuns a HashMap containing the entries and their value.
	 * if not possible - returns null.
	 */
	
	public static HashMap<String,String> ReadConfigurationXML(String path) throws Exception
	{
		HashMap<String,String> cipherConfigurations = new HashMap<>();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc;
		
		try{
		doc = builder.parse(path);
		}catch (Exception e)
		{
			System.out.println("Error reading configurations file "+path+"\nAborting...");
			return null;
		}

		NodeList mainNode = null;
		try
		{
			mainNode = doc.getElementsByTagName("CipherConfigurations");
		}
		catch (Exception e)
		{
			System.out.println("Could not find element EncryptionConfigurations in the configurations file.\nAborting...");
			return null;
		}
		
		if (mainNode.getLength()!=1)
		{
			System.out.println("Wrong structure of cipher configutarion element.\nAborting...");
			return null;
		}
			
		NodeList cipherConfigurationsRoot = (NodeList) mainNode.item(0); // get the root element of the configurations
		System.out.println(cipherConfigurationsRoot.getLength());
		for (int i = 0; i < cipherConfigurationsRoot.getLength(); ++i)
		{
		    Element elem = (Element) cipherConfigurationsRoot.item(i);
		    String paramName = elem.getNodeName();
		    String innerText = elem.getTextContent();
		    cipherConfigurations.put(paramName, innerText);
		}
		
		return cipherConfigurations;
	}
	
}
