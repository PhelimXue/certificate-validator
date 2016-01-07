package com.foxconn.idsbg.cloud.CertificateValidator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.io.pem.PemObject;

public class ValidateKeyAndCertificate {

	public static void main(String[] args) throws Exception {

		String PUBLIC_PATH = "src/file/client.crt";
		String PRIVATE_PATH = "src/file/client.key";
	    Security.addProvider(new BouncyCastleProvider());

	    KeyPair keyPair = readKeyPair(new File(PRIVATE_PATH)); 
	    Key publickey = readPublicKey(new File(PUBLIC_PATH)); 
	    Base64 base64 = new Base64();
	    
	    /*
	     * 第一種方法用一把 key 加密，另一把解密
	     * 作 Decrypt 時會因為解不開而拋 Exception
	     */
	    System.out.println("=========== 加解密法 ===========");
	    String text = "origin text";
	    byte[] encripted;
	    System.out.println("input: " + text);
	    encripted = encrypt(publickey, text);
	    System.out.println("cipher: " + base64.encodeAsString(encripted));
	    String decrypt = decrypt(keyPair.getPrivate(), encripted);
	    System.out.println("decrypt: " + decrypt);
	    System.out.println("match: " + text.equals(decrypt));
	    System.out.println("==============================");
	    
	    /*
	     * 第2種方法 key and crt module 驗證法
	     * 此方法不會拋 Exception 因為 key 和 crt 還是可以取出 id
	     * 可以針對 not match 後作行為
	     */
	    System.out.println("=========== Module ===========");
	    RSAPublicKey rsaPublicKey = (RSAPublicKey) publickey;
        byte[] certModulusData = rsaPublicKey.getModulus().toByteArray();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] certID = sha1.digest(certModulusData);
        String certIDinHex = bytesToHex(certID);
        System.out.println("certificateId: " + certIDinHex);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        byte[] keyModulusData = rsaPrivateKey.getModulus().toByteArray();
        byte[] keyID = sha1.digest(keyModulusData);
        String keyIDinHex = bytesToHex(keyID);
        System.out.println("keyId: " + keyIDinHex);
        System.out.println("match: " + certIDinHex.equals(keyIDinHex));
        System.out.println("==============================");
	}

	private static byte[] encrypt(Key pubkey, String text) {
	    try {
	        Cipher rsa;
	        rsa = Cipher.getInstance("RSA");
	        rsa.init(Cipher.ENCRYPT_MODE, pubkey);
	        return rsa.doFinal(text.getBytes());
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return null;
	}


	private static String decrypt(Key decryptionKey, byte[] buffer) {
	    try {
	        Cipher rsa;
	        rsa = Cipher.getInstance("RSA");
	        rsa.init(Cipher.DECRYPT_MODE, decryptionKey);
	        byte[] utf8 = rsa.doFinal(buffer);
	        return new String(utf8, "UTF8");
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return null;
	}

	/**
	 *  Read Key Pair With Private Key
	 * @param privateKey
	 * @return
	 * @throws IOException
	 */
	private static KeyPair readKeyPair(File privateKey) throws IOException {
	    FileReader fileReader = new FileReader(privateKey);
	    PEMReader r = new PEMReader(fileReader);
	    try {
	        return (KeyPair) r.readObject();
	    } catch (IOException ex) {
	        throw ex;
	    } finally {
	        r.close();
	        fileReader.close();
	    }
	}

	/**
	 * Read Public Key
	 * @param privateKey
	 * @return
	 * @throws IOException
	 * @throws CertificateException
	 */
	private static Key readPublicKey(File privateKey) throws IOException, CertificateException {
	    FileReader fileReader = new FileReader(privateKey);
	    PEMReader r = new PEMReader(fileReader);
	    try {
	    	PemObject certAsPemObject = r.readPemObject();
            if (!certAsPemObject.getType().equalsIgnoreCase("CERTIFICATE")) {
                throw new IllegalArgumentException("Certificate file does not contain a certificate but a " + certAsPemObject.getType());
            }
            byte[] x509Data = certAsPemObject.getContent();
            CertificateFactory fact = CertificateFactory.getInstance("X509");
            Certificate cert = fact.generateCertificate(new ByteArrayInputStream(x509Data));
            if (!(cert instanceof X509Certificate)) {
                throw new IllegalArgumentException("Certificate file does not contain an X509 certificate");
            }

            PublicKey publicKey = cert.getPublicKey();
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Certificate file does not contain an RSA public key but a " + publicKey.getClass().getName());
            }

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
	        return rsaPublicKey;
	    } catch (IOException ex) {
	        throw ex;
	    } finally {
	        r.close();
	        fileReader.close();
	    }
	}
	
	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	private static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
}
