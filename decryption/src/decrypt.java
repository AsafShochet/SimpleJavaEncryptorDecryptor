import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64InputStream;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;


public class decrypt {
    
	public static void main(String args[]) throws Exception
	{
		if (args.length!=2)
		{
			System.out.println("Wrong number of parameters, please insert the path of encryptedTextFile.txt, cipherConfigurations.xml and the path for keystore file.\n" +
					"Make sure that path is ended with '\\\\'. Example:  c:\\\\test\\\\crypto\\\\keyStore.jks c:\\\\test\\\\crypto\\\\"
					+	"\nAborting...\n");
			
			return;
		}
		if (!Files.exists(Paths.get(args[0])))
		{
			System.out.println("Path "+args[0]+" doesn't exist.\nAborting...\n");
			return;
		}
		String basePath = args[0];
		basePath = "c:\\test\\crypto\\";
		
		System.out.println("-------------------------------------------------------------");
		System.out.println("==============================");
		System.out.println("== Receiver\\Decryptor side ==");
		System.out.println("==============================");
		/* Configurations that are known to the receiver */
		HashMap<String,String> receiverConfigurations = new HashMap<>();
		receiverConfigurations.put("encryptedTextFile" ,basePath+"encryptedTextFile.txt");
		receiverConfigurations.put("configurationFile",basePath+"cipherConfigurations.xml");
		receiverConfigurations.put("keyStorePass","J34QqUf");
		receiverConfigurations.put("receiverAlias","decryptorKey");
		receiverConfigurations.put("receiverKeyPass","Hu87Ql");
		receiverConfigurations.put("decryptedTextFile",basePath+"decryptedText.txt");
		receiverConfigurations.put("keyStorePath",basePath+"keystore.jks");
		receiverConfigurations.put("senderAlias","encryptorKey");
		
	
		DecryptFileAndValidateSignature(receiverConfigurations);
		System.out.println("-------------------------------------------------------------");
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
}
