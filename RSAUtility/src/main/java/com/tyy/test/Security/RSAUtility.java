package com.tyy.test.Security;


import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.glassfish.jersey.oauth1.signature.Base64;
import org.glassfish.jersey.oauth1.signature.InvalidSecretException;
import org.glassfish.jersey.oauth1.signature.OAuth1Secrets;
import org.glassfish.jersey.oauth1.signature.OAuth1SignatureMethod;
import org.glassfish.jersey.oauth1.signature.RsaSha1Method;



/**
 * RSA(of length 1000) Signature and Verification, Encryption and Decryption
 * @author tyy
 *
 */
public class RSAUtility{
	
    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    private static final String KEY_TYPE = "RSA";
    private static final int KEY_LENGTH=1024;

    //private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE";
    //public static final String NAME = "RSA-SHA1";
    
    //member is used for save created keyPair and will be accessed in getPrivete() and getPublic()
    KeyPair keyPair;
    
    /**
     * create a RSAUtility Tool class and generate an RSA keyPair meanwhile
     * @throws NoSuchAlgorithmException
     */
    public RSAUtility() throws NoSuchAlgorithmException{
    	getRSAKeyPair();
    }
    
    /**
     * Only used when you need create many RSA key pairs
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair getRSAKeyPairStatic() throws NoSuchAlgorithmException{
    	KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_TYPE);  
        //初始化密钥对生成器，密钥大小为1024位  
        keyPairGen.initialize(KEY_LENGTH);  
        //生成一个密钥对，保存在keyPair中  
        KeyPair keyPair = keyPairGen.generateKeyPair(); 
        return keyPair;
    }
    /**
     * generate an RSA key pair(which contains info of private key and public key)
     * @return
     * @throws NoSuchAlgorithmException
     */
    private  KeyPair getRSAKeyPair() throws NoSuchAlgorithmException{
    	if(this.keyPair==null) {
    		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_TYPE);  
            //初始化密钥对生成器，密钥大小为1024位  
            keyPairGen.initialize(KEY_LENGTH);  
            //生成一个密钥对，保存在keyPair中  
            this.keyPair = keyPairGen.generateKeyPair(); 
    	}
    	return this.keyPair;
    }
    
    /**
     * get RSAPrivateKey contained in keyPair member generated before
     * @return
     * @throws NoSuchAlgorithmException
     */
    public RSAPrivateKey getPrivate() throws NoSuchAlgorithmException{
    	if(this.keyPair==null){
    		getRSAKeyPair();
    	}
    	return (RSAPrivateKey)this.keyPair.getPrivate();
    }
    
    /**
     * get RSAPublicKey contained in keyPair member generated before
     * @return
     * @throws NoSuchAlgorithmException
     */
    public RSAPublicKey getPublic() throws NoSuchAlgorithmException{
    	if(this.keyPair==null){
    		getRSAKeyPair();
    	}
    	return (RSAPublicKey)this.keyPair.getPublic();
    }
    
    /**
     * get "SHA1withRSA" signature
     * @param baseString: the String is supposed to hashed and RSA Private Key Encoded
     * @param oraprivateKey: RSA Private Key
     * @return
     * @throws InvalidSecretException
     */
    public static String getSignature(String baseString, RSAPrivateKey oraprivateKey) throws InvalidSecretException {
    	OAuth1Secrets oAuthSecrets=new OAuth1Secrets();
        oAuthSecrets.setConsumerSecret( Base64.encode( oraprivateKey.getEncoded() ) );
 		
        OAuth1SignatureMethod signatureMethod=new RsaSha1Method();
        
        String signedString;
 		try {
 			signedString=signatureMethod.sign(baseString, oAuthSecrets);
 			return signedString;
 		} catch (InvalidSecretException e) {
 			// TODO Auto-generated catch block
 			throw new InvalidSecretException();
 		}
    }
    
    /**
     * Verify the signature, that is to see: RSA(orapublicKey, signature) == SHA1(baseString) ? true : false
     * @param baseString
     * @param signature
     * @param orapublicKey
     * @return
     * @throws IOException
     */
    public static boolean verifySignature(String baseString, String signature, RSAPublicKey orapublicKey) throws IOException {
    	final Signature sig;
		try {
            sig = Signature.getInstance(SIGNATURE_ALGORITHM);	//SHA1withRSA
        } catch (final NoSuchAlgorithmException nsae) {
            throw new IllegalStateException(nsae);
        }
		
		final byte[] decodedSignature;
        try {
            decodedSignature = Base64.decode(signature);
        } catch (final IOException e) {
            throw new IOException("signature base64 decode error");
        }
		
        try {
            sig.initVerify(orapublicKey);
        } catch (final InvalidKeyException ike) {
            throw new IllegalStateException(ike);
        }

        try {
            sig.update(baseString.getBytes());
        } catch (final SignatureException se) {
            throw new IllegalStateException(se);
        }
        
        try {
        	return sig.verify(decodedSignature);
        } catch (final SignatureException se) {
            throw new IllegalStateException(se);
        }
    }
    
    /**
     * when a host(who generate the RSA key pair) sends a message, he encrypt his message with his RSA Private Key
     * @param hostPrivateKey
     * @param srcBytes
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] hostEncrypt(RSAPrivateKey hostPrivateKey, byte[]srcBytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
    	Cipher cipher = Cipher.getInstance( KEY_TYPE );
        cipher.init(Cipher.ENCRYPT_MODE, hostPrivateKey);
        byte[] targetByte=cipher.doFinal(srcBytes);
        return targetByte;
    }
    /**
     * when a client(who get the RSA Public Key from a host) receives a message, he decrypt the message with RSA Public Key
     * @param rsaPublicKey
     * @param srcBytes
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] clientDecrypt(RSAPublicKey rsaPublicKey, byte[]srcBytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
    	Cipher cipher = Cipher.getInstance( KEY_TYPE );
        cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        byte[] targetByte=cipher.doFinal(srcBytes);
        return targetByte;
    }
    
    /**
     * when a client(who get the RSA Public Key from a host) sends a message, he encrypt his message with RSA Public Key
     * @param rsaPublicKey
     * @param srcBytes
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] clientEncrypt(RSAPublicKey rsaPublicKey, byte[]srcBytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
    	Cipher cipher = Cipher.getInstance( KEY_TYPE );
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] targetByte=cipher.doFinal(srcBytes);
        return targetByte;
    }
    /**
     * when a host(who generate the RSA key pair) receives a message, he decrypt the message with his RSA Private Key
     * @param hostPrivateKey
     * @param srcBytes
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] hostDecrypt(RSAPrivateKey hostPrivateKey, byte[]srcBytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
    	Cipher cipher = Cipher.getInstance( KEY_TYPE );
        cipher.init(Cipher.DECRYPT_MODE, hostPrivateKey);
        byte[] targetByte=cipher.doFinal(srcBytes);
        return targetByte;
    }
    
    
	public static void main(String[]args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidSecretException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String baseString="hello RSA";
		//获取工具类
		RSAUtility rsa=new RSAUtility();
       //得到数字签名
       String signature=getSignature(baseString, rsa.getPrivate());
       //数字签名验证
       boolean verifyResult= verifySignature(baseString, signature, rsa.getPublic());
       
       System.out.println(verifyResult);
       
       
       /**
        * test encryption and decryption
        */
       String srcString="hello RSA. Source String";
       /*
       byte[] target=hostEncrypt(rsa.getPrivate(),srcString.getBytes());
       System.out.println(Base64.encode(target));
       byte[] target2=clientDecrypt(rsa.getPublic(),target);
       String target2String=new String(target2);
       System.out.println(target2String);
       System.out.println(srcString.equals(target2String));
       */
       
       /**
        * 加密解密测试。这也证明了RSA非对称加密算法密钥的对等性（即公钥私钥可以互相加密解密）
        */
       boolean shouldBeTrue=new String( clientDecrypt( rsa.getPublic(),hostEncrypt(rsa.getPrivate(),srcString.getBytes()) ) ).equals(srcString);
       System.out.println(shouldBeTrue);
       boolean shouldBeTrue2=new String( hostDecrypt( rsa.getPrivate(),clientEncrypt(rsa.getPublic(),srcString.getBytes()) ) ).equals(srcString);
       System.out.println(shouldBeTrue2);
	}

}
