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
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
/**
 * @author Asaf Shochet
 * @email wasafa1@gmail.com
 * @Date 14/12/2013
 *
 */
public class cryptoClass {
	

	/*
	 * Main access point to the program
	 * Contains:
	 * File variables are set (names, paths, passwords)
	 * Cipher algorithms (Algorithms,Providers,Padding configurations)
	 * Data visible to sender
	 * Data visible to receiver
	 */
	static public void main(String args[]) throws Exception 
	{
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
		
		/*Data for configurations XML file (known to sender)*/
		HashMap<String,String> configurationData = new HashMap<>();
		configurationData.put("encryptionAlgoForSymmetricKey","AES/CBC/PKCS5PADDING"); // Algorithm for symmetric encryption of the text file
		configurationData.put("encryptionAlgoForSymmetricKeyProvider","SunJCE"); //Setting provider for symmmetric encryption
		 
		configurationData.put("encryptionAlgoForKeyGeneration","AES"); // Encryption algorithm for key generation
		configurationData.put("encryptionAlgoForKeyGenerationProvider","SunJCE"); //Setting provider for key generation
		
		configurationData.put("encryptionAlgoForSendingSharedKey","RSA/ECB/PKCS1Padding"); // Encryption algorithm for sending shared Key
		configurationData.put("encryptionAlgoForSendingSharedKeyProvider","SunJCE"); //Setting provider for sending shared Key
		
		configurationData.put("digitalSignatureAlgorithm","MD5withRSA"); // Digital signature algorithm
	    
		System.out.println("============================");
		System.out.println("== Sender\\Encryptor side ==");
		System.out.println("============================");
		EncryptAndSignAFile(senderConfigurations,configurationData,receiverConfigurations);
		System.out.println("-------------------------------------------------------------");
		System.out.println("==============================");
		System.out.println("== Receiver\\Decryptor side ==");
		System.out.println("==============================");
		DecryptFileAndValidateSignature(receiverConfigurations);
		System.out.println("-------------------------------------------------------------");
		
		}
	/* 
	 * Encrypts and Signs a clear text file to be send between a sender and a receiver, in the following way:
	 * 1. Generates a symmetric key SK
	 * 2. Uses SK to encrypt the clear text file
	 * 3. Reads receiver's public key, and encrypts SK with it (Asymetric encryption)
	 * 4. Signs the clear text file using sender's private key
	 * 5. Generates a cipher configurations XML file (includes digital signature), to be sent to the receiver with the encrypted file
	 */ 
	static public boolean EncryptAndSignAFile(HashMap<String,String> senderConfigurations,HashMap<String,String> configurationData,HashMap<String,String> receiverConf) throws Exception
	{
		/* Generate symmetric key for AES-CBC encryption of the file */
		
		Key sharedKey = KeyGenerator.getInstance(configurationData.get("encryptionAlgoForKeyGeneration"), configurationData.get("encryptionAlgoForKeyGenerationProvider")).generateKey(); // generate symetric key
		Cipher encryptor = Cipher.getInstance(configurationData.get("encryptionAlgoForSymmetricKey"), configurationData.get("encryptionAlgoForSymmetricKeyProvider"));
		byte[] iv = new byte[encryptor.getBlockSize()]; // create IV byte array
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(iv); // generate random iv
		IvParameterSpec ivspec = new IvParameterSpec(iv); // initialize IV
		
		System.out.println("Generated a shared key for symmetric encryption.");
		/* Encrypt the file */
		EncryptFile(senderConfigurations.get("fileToEncrypt"),senderConfigurations.get("encryptedTextFile"),encryptor,sharedKey, ivspec);  // Encrypts file with symetric key and writes cipher into encryptedTextFile
		System.out.println("Encrypted file "+senderConfigurations.get("fileToEncrypt")+" using "+encryptor.getAlgorithm()+" in path "+senderConfigurations.get("encryptedTextFile"));
		
		/* Save Configurations into configuration file encrypted by public key of the receiver*/
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(senderConfigurations.get("keyStorePath"));
        ks.load(ksStream, senderConfigurations.get("keyStorePass").toCharArray());
        PublicKey receiverPublicKey = ks.getCertificate(senderConfigurations.get("receiverAlias")).getPublicKey(); //receiverPublicKey holds the public key for receiver
     
        Cipher rsaEncryptor = Cipher.getInstance(configurationData.get("encryptionAlgoForSendingSharedKey"), configurationData.get("encryptionAlgoForSendingSharedKeyProvider")); // encryptor for the secret key
        byte[] symetricKeyEncrypted = EncryptText(sharedKey.getEncoded(),rsaEncryptor,receiverPublicKey, null);  // Encrypts the symetric key using public key of the reciever
        System.out.println("Encrypted symmetric key using receiver's public key.");
        configurationData.put("symetricKeyEncrypted",Base64.encodeBase64String(symetricKeyEncrypted));
        byte[] ivEncrypted =EncryptText(ivspec.getIV(),rsaEncryptor,receiverPublicKey, null);
        configurationData.put("ivspec",Base64.encodeBase64String(ivEncrypted));
        /* Create configuration XML */ 
      
        /* Calculate digital signature */
        PrivateKey senderPrivateKey = (PrivateKey) ks.getKey(senderConfigurations.get("senderAlias"), senderConfigurations.get("enctyptorKeyPass").toCharArray()); //publicKey holds the public key for sender
        byte[] digitalSignature = CalculateDigitalSignature(senderConfigurations.get("fileToEncrypt"),configurationData.get("digitalSignatureAlgorithm"),senderPrivateKey);
        
        System.out.println("Calculated file digital signature using "+configurationData.get("digitalSignatureAlgorithm"));
		configurationData.put("digitalSignature",Base64.encodeBase64String(digitalSignature));
		
		/* Creating XML cipher configurations file */
      	if (!CreateCipherConfigurationXML(configurationData, senderConfigurations.get("configurationFile"))) 
		System.out.println("Error creating configuration file.\nAborting...\n");
      	System.out.println("Cipher configurations XML file created by sender in path "+senderConfigurations.get("configurationFile"));

		return true;
    		
	}
	
	/* 
	 * Decrypts and validates a signature of an encrypted file that was sent between a sender and a receiver, in the following way:
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
		System.out.println("Read data Cipher configurations XML."); 		
		/* Initialize the encryptor */
		Cipher encryptor = Cipher.getInstance(cipherConfigurations.get("encryptionAlgoForSymmetricKey"), cipherConfigurations.get("encryptionAlgoForSymmetricKeyProvider"));

        /* Get data from cipher configurations XML*/
		byte[] symetricKeyEncrypted =Base64.decodeBase64(cipherConfigurations.get("symetricKeyEncrypted"));
		/* Initialize the symmetric key encryptor */
		Cipher rsaEncryptor = Cipher.getInstance(cipherConfigurations.get("encryptionAlgoForSendingSharedKey"), cipherConfigurations.get("encryptionAlgoForSendingSharedKeyProvider")); // encryptor for the secret key
	    byte[] symetricKeyDecrypted = DecryptText(symetricKeyEncrypted,rsaEncryptor,receiverPrivateKey, null);
        
		byte[] ivConfig =Base64.decodeBase64(cipherConfigurations.get("ivspec"));
		byte[] iv = DecryptText(ivConfig, rsaEncryptor, receiverPrivateKey, null);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		byte[] digitalSignature = Base64.decodeBase64(cipherConfigurations.get("digitalSignature"));
		
		Key symmetricKeyAfterDecription =  new SecretKeySpec(symetricKeyDecrypted, cipherConfigurations.get("encryptionAlgoForKeyGeneration")); //build a new secret key from text
		System.out.println("Decrypted symmetric key using his own private key");
		
       	/* Decrypt file into decryptedFile */
        DecryptFile(receiverConfigurations.get("encryptedTextFile"), receiverConfigurations.get("decryptedTextFile"), encryptor, symmetricKeyAfterDecription,ivSpec);
        System.out.println("Decrypted text file "+receiverConfigurations.get("encryptedTextFile")+" into "+receiverConfigurations.get("decryptedTextFile")); 		
		
        /* Verify digital signature */
        PublicKey senderPublicKey = ks.getCertificate(receiverConfigurations.get("senderAlias")).getPublicKey(); //publicKey holds the public key for sender
        boolean signatureValidated = ValidateDigitalSignature(receiverConfigurations.get("decryptedTextFile"),cipherConfigurations.get("digitalSignatureAlgorithm"),senderPublicKey,digitalSignature);

        if (!signatureValidated)
        {
        	System.out.println("Error decrypting text or validating digital signature.\nAborting...");
        	return false;
        }
        else
        {
        	System.out.println("File was successfully decrypted, digital signature was successfully validated.\n");
        	return true;
        }
       
       }
	
		
	/* 
	 * Simulates the process where the receiver is calculating the signature of a message he received
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

	/* 
	 * Reads a file and encrypts it using a Cipher object (encryptor).
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
			cos.write(block,0, i); // write each block encrypted to the output file converted to base64
			}
		}
		cos.close(); // close output file
		b64os.close();
		fis.close();
		fos.close();
	}
		
	/* 
	 * Reads a file and encrypts it using a Cipher object (encryptor).
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
	
	/* 
	 * Reads an encrypted text and decrypts it using a Cipher object (encryptor).
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
		
	/* 
	 * Reads an encrypted text file and decrypts it using a Cipher object (encryptor).
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
	 * Creates file and its paths if not exist.
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

	/* 
	 * Creates an xml file in path that keeps all configurations for the Cipher element */
	public static boolean CreateCipherConfigurationXML(HashMap<String,String> dataToWrite, String path) throws Exception
	{
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
