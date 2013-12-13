/* Imports */
 
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

import com.sun.org.apache.xerces.internal.impl.XML11DocumentScannerImpl;
import com.sun.org.apache.xerces.internal.util.XML11Char;

import java.security.KeyStore;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
public class cryptoClass {
	
	static public void main(String args[]) throws Exception 
	{
		/* Constants */
		/* File paths*/
		String fileToEncrypt = "c:\\test\\crypto\\fileToEncrypt.txt";
		String encryptedTextFile = "c:\\test\\crypto\\encryptedTextFile.txt";
		String decryptedTextFile = "c:\\test\\crypto\\decryptedText.txt";
		String keyStorePath = "c:\\test\\crypto\\crypto\\keystore.jks";
		String configurationFile = "c:\\test\\crypto\\cipherConfigurations.xml";
		
		/* Passwords */
		String keyStorePass= "Gr8Pass";
		String encryptorAlias = "encryptorKey";
		String enctyptorKeyPass = "Gr8Pass";
		String decryptorAlias = "decryptorKey";
		String decryptorKeyPass = "HalvaOle";
		
		/*Data for configurations XML file*/
		
		HashMap<String,String> configurationData = new HashMap();
		configurationData.put("encryptionType","AES/CBC/NoPadding"); // AES algorithm in CBC mode Encryption algorithm
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
		
		EncryptFile(fileToEncrypt,encryptedTextFile,encryptor,sharedKey, ivspec);  // Encrypts file with symetric key and writes cipher into encryptedTextFile
	
		/* Save Configurations into configuration file encrypted by public key of the decryptor*/
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(keyStorePath);
        ks.load(ksStream, keyStorePass.toCharArray());
        PublicKey decryptorPublicKey = ks.getCertificate(decryptorAlias).getPublicKey(); //decryptorPublicKey holds the public key for decryptor
        PrivateKey decryptorPrivateKey =  (PrivateKey) ks.getKey(decryptorAlias, decryptorKeyPass.toCharArray()); //private key of decryptor
        Cipher rsaEncryptor = Cipher.getInstance(configurationData.get("encryptionAlgoForSecretKey")); // encryptor for the secret key
        
        
        
        byte[] symetricKeyEncrypted = EncryptText(sharedKey.getEncoded(),rsaEncryptor,decryptorPublicKey, null);  // Encrypts the symetric key using public key of the reciever
        byte[] symetricKeyDecrypted = DecryptText(symetricKeyEncrypted,rsaEncryptor,decryptorPrivateKey, null);
        Key symmetricKeyAfterDecription =  new SecretKeySpec(symetricKeyDecrypted, configurationData.get("encryptionAlgoForKeyGen")); //build a new secret key from text
        System.out.println(sharedKey);
        System.out.println(symmetricKeyAfterDecription);
        if (symmetricKeyAfterDecription.equals(symmetricKeyAfterDecription))
        	System.out.println("Equal");
        configurationData.put("symetricKeyEncrypted",symetricKeyEncrypted.toString());
        /* Save digital signature into digSin.txt and encrypt it by encryptor private key*/
        PrivateKey encryptorPrivateKey = (PrivateKey) ks.getKey(encryptorAlias, enctyptorKeyPass.toCharArray()); //publicKey holds the public key for encryptor
        byte[] digitalSignature = CalculateDigitalSignature(fileToEncrypt,configurationData.get("digitalSignatureAlgorithm"),encryptorPrivateKey);
        configurationData.put("digitalSignature",digitalSignature.toString());
        
        /* Create configuration XML */ 
		if (!CreateConfigurationXML(configurationData, configurationFile)) 
		{System.out.println("Error creating configuration file.\nAborting...\n");
		return;
		}
		
		
        boolean decryptionOK = DecryptFileAndValidateSignature(keyStorePath,keyStorePass,encryptorAlias,enctyptorKeyPass,decryptedTextFile, encryptedTextFile,encryptor,sharedKey,ivspec,configurationData.get("digitalSignatureAlgorithm"),digitalSignature);
        return;		
	}
	
	private static boolean DecryptFileAndValidateSignature(String keyStorePath,String keyStorePass, String encryptorAlias, String enctyptorKeyPass, String decryptedFile, String encryptedTextFile,Cipher encryptor, Key sharedKey,IvParameterSpec ivspec, String digitalSignatureAlgorithm, byte[] digitalSignature) throws Exception {
		
		KeyStore ks = KeyStore.getInstance("jks"); // Load public key from keyStore
		FileInputStream ksStream = new FileInputStream(keyStorePath);
        ks.load(ksStream, keyStorePass.toCharArray());
        
		/* Decrypt file into decryptedFile */
        Key key = ks.getKey(encryptorAlias, enctyptorKeyPass.toCharArray());
        DecryptFile(encryptedTextFile, decryptedFile, encryptor, sharedKey,ivspec);
        
        /* Verify digital signature */
        PublicKey encryptorPublicKey = ks.getCertificate(encryptorAlias).getPublicKey(); //publicKey holds the public key for encryptor
        boolean signatureValidated = ValidateDigitalSignature(decryptedFile,digitalSignatureAlgorithm,encryptorPublicKey,digitalSignature);
        System.out.println(signatureValidated);
        return signatureValidated;
	}

	private static boolean ValidateDigitalSignature(String decryptedFile,
			String digitalSignatureAlgorithm, PublicKey encryptorPublicKey, byte[] signatureToVerify) throws Exception {
		Signature dsa = Signature.getInstance(digitalSignatureAlgorithm);       /* Initializing the object with the digital signature algorithm */ 
        dsa.initVerify(encryptorPublicKey); 
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
			String digitalSignatureAlgorithm, PrivateKey encryptorPrivateKey)   throws Exception{
		
			Signature dsa = Signature.getInstance(digitalSignatureAlgorithm);       /* Initializing the object with the digital signature algorithm */
		    dsa.initSign(encryptorPrivateKey); 
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

	/// Reads file and encrypts it line by line into 
	private static void EncryptFile(String inputFile,String outputFile, Cipher encryptor, Key key, IvParameterSpec ivspec) throws Exception
	{
		assert (CreateFileIfNecessery(outputFile) == true); //creates output file if necessery
		FileInputStream fis = new FileInputStream(inputFile); 
		FileOutputStream fos = new FileOutputStream(outputFile);
		CipherOutputStream cos = new CipherOutputStream(fos, encryptor);
		encryptor.init(Cipher.ENCRYPT_MODE, key, ivspec);  // initialize cipher in ecryption mode
		byte[] block = new byte[8];
		int i;
		while ((i = fis.read(block)) != -1) { //read all blocks in file
			{
			cos.write(block,0, i); // write each block encrypted to the output file converted to base64
			
			}
		}
		cos.close(); // close output file
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
		FileOutputStream fos = new FileOutputStream(outputFile);
		CipherInputStream cis = new CipherInputStream(fis, encryptor);
		encryptor.init(Cipher.DECRYPT_MODE, key, ivspec); //initilize cipher in decryption mode with IV
				
		byte[] block = new byte[8];
		int i;
		while ((i = cis.read(block)) != -1) { //read all blocks in file
			{
				fos.write(block,0, i); // write each block encrypted to the output file
			}
		}
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
 
		System.out.println(source.toString());
		transformer.transform(source, result);
 
		
		return true;
	}
	
	public static HashMap<String,String> ReadConfigurationXML(String path) throws Exception
	{
		return null;
	}
	
}