/* Imports */
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64OutputStream;

import java.io.File;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
 
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyStore;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
/**
 * @author Asaf Shochet
 * @email wasafa1@gmail.com
 * @Date 14/12/2013
 */
public class Encryptor {
	/*
	 * Main access point to the program
	 * Contains:
	 * File variables are set (names, paths, passwords)
	 * Cipher algorithms (Algorithms,Providers,Padding configurations) - can change them easily
	 * Data visible to sender
	 * Data visible to receiver
	 */
	static public void main(String args[]) throws Exception 
	{
		if (args.length!=3)
		{
			System.out.println("Wrong number of parameters, please insert the path of file to encrypt, path of keyStore.jks and output folder.\n" +
					"Make sure that path is ended with '\\\\'.\n Example: c:\\\\test\\\\fileToEncrypt.txt c:\\\\test\\\\keyStore.jks c:\\\\outputFolder\\\\\nAborting...\n");
			return;
		}
		
		String basePath = args[2];
		/* Configurations that are known to the sender */
		HashMap<String,String> senderConfigurations = new HashMap<>();
		senderConfigurations.put("fileToEncrypt", args[0]);
		senderConfigurations.put("encryptedTextFile" ,basePath+"encryptedTextFile.txt");
		senderConfigurations.put("configurationFile",basePath+"cipherConfigurations.xml");
		senderConfigurations.put("keyStorePath",args[1]);
		senderConfigurations.put("keyStorePass","J34QqUf");
		senderConfigurations.put("senderAlias","encryptorKey");
		senderConfigurations.put("enctyptorKeyPass","U8MyK7");
		senderConfigurations.put("receiverAlias","decryptorKey");
			
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
		EncryptAndSignAFile(senderConfigurations,configurationData);
			
		}
	/* 
	 * Encrypts and Signs a clear text file to be send between a sender and a receiver, in the following way:
	 * 1. Generates a symmetric key SK
	 * 2. Uses SK to encrypt the clear text file
	 * 3. Reads receiver's public key, and encrypts SK with it (Asymetric encryption)
	 * 4. Signs the clear text file using sender's private key
	 * 5. Generates a cipher configurations XML file (includes digital signature), to be sent to the receiver with the encrypted file
	 */ 
	static public boolean EncryptAndSignAFile(HashMap<String,String> senderConfigurations,HashMap<String,String> configurationData) throws Exception
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
	
	
	
}
