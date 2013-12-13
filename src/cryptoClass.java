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
public class cryptoClass {
	
	
	/* Encrypts and Signs a clear text file to be send between a sender and a receiver, in the following way:
	 * 1. Generates a symmetric key SK
	 * 2. Uses SK to encrypt the clear text file
	 * 3. Reads receiver's public key, and encrypts SK with it (Asymetric encryption)
	 * 4. Signs the clear text file using sender's private key
	 * 5. Generates a configuration XML file (includes digital signature), to be sent to the receiver with the encrypted file
	 */ 
	static public boolean EncryptAndSignAFile(HashMap<String,String> senderConfigurations,HashMap<String,String> configurationData )
	{
		return true;
		
	}
	static public void main(String args[]) throws Exception 
	{
		mainProgram();
		
		
	}
	
	
	public static void mainProgram() throws Exception
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
		configurationData.put("encryptionAlgoForSecretKey","RSA");
		configurationData.put("digitalSignatureAlgorithm","MD5withRSA");
	    
		/* End of Paths and key names */
		
		
		/* Generate symmetric key for AES-CBC encryption of the file */
		Key sharedKey = (KeyGenerator.getInstance(configurationData.get("encryptionAlgoForKeyGen"))).generateKey(); // generate symetric key
		Cipher encryptor = Cipher.getInstance(configurationData.get("encryptionType"));
		
		byte[] iv = new byte[encryptor.getBlockSize()]; // create IV byte array
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(iv); // generate random iv
		IvParameterSpec ivspec = new IvParameterSpec(iv); // initialize IV
		
		EncryptFile(senderConfigurations.get("fileToEncrypt"),senderConfigurations.get("encryptedTextFile"),encryptor,sharedKey, ivspec);  // Encrypts file with symetric key and writes cipher into encryptedTextFile
	
		/* Save Configurations into configuration file encrypted by public key of the receiver*/
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(senderConfigurations.get("keyStorePath"));
        ks.load(ksStream, senderConfigurations.get("keyStorePass").toCharArray());
        PublicKey receiverPublicKey = ks.getCertificate(senderConfigurations.get("receiverAlias")).getPublicKey(); //receiverPublicKey holds the public key for receiver
        PrivateKey receiverPrivateKey =  (PrivateKey) ks.getKey(receiverConfigurations.get("receiverAlias"), receiverConfigurations.get("receiverKeyPass").toCharArray()); //private key of receiver
        Cipher rsaEncryptor = Cipher.getInstance(configurationData.get("encryptionAlgoForSecretKey")); // encryptor for the secret key
        
        byte[] symetricKeyEncrypted = EncryptText(sharedKey.getEncoded(),rsaEncryptor,receiverPublicKey, null);  // Encrypts the symetric key using public key of the reciever
        byte[] symetricKeyDecrypted = DecryptText(symetricKeyEncrypted,rsaEncryptor,receiverPrivateKey, null);
        Key symmetricKeyAfterDecription =  new SecretKeySpec(symetricKeyDecrypted, configurationData.get("encryptionAlgoForKeyGen")); //build a new secret key from text
        System.out.println(sharedKey);
        System.out.println(symmetricKeyAfterDecription);
        if (symmetricKeyAfterDecription.equals(symmetricKeyAfterDecription))
        	System.out.println("Equal");
        configurationData.put("symetricKeyEncrypted",symetricKeyEncrypted.toString());
        /* Save digital signature into digSin.txt and encrypt it by encryptor private key*/
        PrivateKey senderPrivateKey = (PrivateKey) ks.getKey(senderConfigurations.get("senderAlias"), senderConfigurations.get("enctyptorKeyPass").toCharArray()); //publicKey holds the public key for sender
        byte[] digitalSignature = CalculateDigitalSignature(senderConfigurations.get("fileToEncrypt"),configurationData.get("digitalSignatureAlgorithm"),senderPrivateKey);
        configurationData.put("digitalSignature",digitalSignature.toString());
        
        /* Create configuration XML */ 
		if (!CreateConfigurationXML(configurationData, senderConfigurations.get("configurationFile"))) 
		{System.out.println("Error creating configuration file.\nAborting...\n");
		return;
		}
		
        boolean decryptionOK = DecryptFileAndValidateSignature(receiverConfigurations.get("keyStorePath"),receiverConfigurations.get("keyStorePass"),receiverConfigurations.get("senderAlias"),receiverConfigurations.get("senderKeyPass"),receiverConfigurations.get("decryptedTextFile"), receiverConfigurations.get("encryptedTextFile"),encryptor,sharedKey,ivspec,configurationData.get("digitalSignatureAlgorithm"),digitalSignature);
        System.out.println(decryptionOK);
        return;		
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
	        return sig;
	}

	/// Reads file and encrypts it line by line, also encodes it
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
		
	public static byte[] EncryptText(byte[] text, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		OutputStream os = new ByteArrayOutputStream();
		InputStream is = new ByteArrayInputStream(text);
		CipherOutputStream cos = new CipherOutputStream(os, encryptor);
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
	
	public static byte[] DecryptText(byte[] text, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		OutputStream os = new ByteArrayOutputStream();
		InputStream is = new ByteArrayInputStream(text);
		CipherInputStream cis = new CipherInputStream(is, encryptor);
		encryptor.init(Cipher.DECRYPT_MODE, key, ivspec); //initilize cipher in decryption mode with IV
		byte[] block = new byte[8];
		int i;	
		while ((i = cis.read(block)) != -1) { //read all blocks in file
			{
				os.write(block,0, i); // write each block encrypted to the output file
			}
		}
		os.close(); // close output file
		is.close(); // close input file
		cis.close();
		return ((ByteArrayOutputStream) os).toByteArray();
	}
		
	
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
		
	private static boolean CreateFileIfNecessery(String path) throws Exception
	{
		File f = new File(path);
		if (!f.mkdirs()) return false; //creates the directories for the file
		if (!f.createNewFile()) return false; // creates the output file
		return true;
	}

	// Read lines from a file in filePath
	public static List<String> ReadLinesFromFile(String filePath)
	{
		List<String> fileLines;
		Path file = Paths.get(filePath);
		try{
		fileLines = Files.readAllLines(file, Charset.forName("UTF-8"));
		}
		catch (Exception e)
		{
			System.out.println(String.format("Problem reading file %s",filePath));
			return null;
		}
		return fileLines;
	}
	
	public static boolean CreateConfigurationXML(HashMap<String,String> dataToWrite, String path) throws Exception
	{
	//	assert (CreateFileIfNecessery(path) == true);
	
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
 
		// root elements
		Document doc = docBuilder.newDocument();
		Element rootElement = doc.createElement("EncryptionConfigurations");
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
	
	public static HashMap<String,String> ReadConfigurationXML(String path) throws Exception
	{
		return null;
	}
	
}
