package com.tyy.test.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.glassfish.jersey.oauth1.signature.Base64;


/**
 * AES encryption and decryption implementation in Java
 * @author tyy
 *
 */
public class AESUtility {
	
	public static String TYPE="AES";
	static final int GROUP_SIZE=15;
	static final int AES_SIZE=16;
	
	private static SecretKey generateSecretKey(String aesPassword) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		KeyGenerator keyGen = KeyGenerator.getInstance(TYPE);
		keyGen.init(new SecureRandom( aesPassword.getBytes("utf-8") ) );
		return keyGen.generateKey();
	}
	
	public static byte[] encrypt(byte[] data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), TYPE);
		Cipher cipher = Cipher.getInstance(TYPE);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		cipher.update(data);
		return cipher.doFinal();
	}
	public static byte[] decrypt(byte[] secretData, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), TYPE);
		Cipher cipher = Cipher.getInstance(TYPE);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		cipher.update(secretData);
		return cipher.doFinal();
	}
	
	/**
	 * split data into size 15 byte array, the output byte array size is constantly 15 byte array.
	 * After Base64 encoding, we get length 20 Base64 encoded String
	 * @param data
	 * @param secretKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptLongByte(byte[] data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), TYPE);
		Cipher cipher = Cipher.getInstance(TYPE);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] returned = new byte[ ((data.length-1)/GROUP_SIZE+1)*AES_SIZE ];
		int dataPos=0;
		int targetPos=0;
		while(dataPos<data.length) {
			int iBefore=dataPos;
			if(dataPos+GROUP_SIZE>=data.length){
				dataPos=data.length;
			}else{
				dataPos+=GROUP_SIZE;
			}
			cipher.update( Arrays.copyOfRange(data, iBefore, dataPos) );
			System.arraycopy( cipher.doFinal() ,  0,  returned, targetPos, AES_SIZE);
			targetPos+=16;
		}
		return returned;
	}
	
	/**
	 * split secretData into AES_SIZE(default is 16) group, 
	 * and decrypt them into 15-size data group 
	 * and them glue these byte arrays into a whole
	 * @param secretData
	 * @param secretKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptLongByte(byte[] secretData, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), TYPE);
		Cipher cipher = Cipher.getInstance(TYPE);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		
		cipher.update( Arrays.copyOfRange(secretData, secretData.length-AES_SIZE, secretData.length) );
		byte[] tailDecrypted = cipher.doFinal();
		byte[] returned=new byte[(secretData.length/AES_SIZE-1)*GROUP_SIZE + tailDecrypted.length];
		System.arraycopy(tailDecrypted, 0, returned, returned.length-tailDecrypted.length, tailDecrypted.length);
		
		int secretPos=0;
		int targetPos=0;
		byte[] todo =new byte[AES_SIZE];
		while(secretPos<secretData.length-AES_SIZE){
			System.arraycopy(secretData, secretPos, todo, 0, AES_SIZE);
			cipher.update(todo);
			System.arraycopy(cipher.doFinal(), 0, returned, targetPos, GROUP_SIZE);
			secretPos+=AES_SIZE;
			targetPos+=GROUP_SIZE;
		}
		return returned;
	}
	
	
	public static void main(String[]args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		SecretKey secretKey=generateSecretKey("abc");
		String message1="123456789ABCDEF";
		String message2="abcd";
		try{
			byte[] encrypteda = encrypt(message1.getBytes(), secretKey);
			System.out.println( Arrays.toString(encrypteda) );
			byte[] encryptedb = encrypt(message2.getBytes(), secretKey);
			System.out.println( Arrays.toString(encryptedb) );
			
			byte[] encrypted2 = encryptLongByte(( ".:';';\"" ).getBytes(), secretKey);
			System.out.println( Arrays.toString(encrypted2) );
			
			byte[] decrypted2 = decryptLongByte(encrypted2,secretKey);
			System.out.println(Arrays.toString( decrypted2 ));
			System.out.println(new String(decrypted2));
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
}

