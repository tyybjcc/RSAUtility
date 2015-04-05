package com.tyy.test.security;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;








import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.glassfish.jersey.oauth1.signature.Base64;
import org.glassfish.jersey.oauth1.signature.internal.LocalizationMessages;

public class RSAEncodingAndDecoding {
	static final String KEY_TYPE="RSA";
	
	static final String pub="AAAAB3NzaC1yc2EAAAADAQABAAAAgQCv1006y05GUfi8eT/fI+LxSa5A/GcL1+QsY1pk22LEb18X/qw+qf6PnySkKOPBU0wH9iOCLgQh6Gi5CTAuVOG/zda+BOwq8UX0hR84HDuMy7047foJMdmvG0D1YN9jPuZL5jQU0ZooMfBfd1QfXDH2TgLnuKe6vOa1MrUxAnCDhw==";
	static final String pri="MIICXAIBAAKBgQCv1006y05GUfi8eT/fI+LxSa5A/GcL1+QsY1pk22LEb18X/qw+qf6PnySkKOPBU0wH9iOCLgQh6Gi5CTAuVOG/zda+BOwq8UX0hR84HDuMy7047foJMdmvG0D1YN9jPuZL5jQU0ZooMfBfd1QfXDH2TgLnuKe6vOa1MrUxAnCDhwIDAQABAoGBAIOl4/JCyCWptVoWRRWg3oXbrhSFY/jf97qr379m6Pk8kKt8RiTcTPPmKB6nZm0VGfVT+J28KefhApaWJHZrol8hpd/61rBOXo97fF0aAYsuVxaylGlkbPETk54Pn+fUgYP/JQzGbHgKjnrErlPpw+MmUUH5NdVKRiqyDZpQJNQRAkEA7tc1OiYhSQl+8k5MwiY0WN3nDOcyl9to7rvrODPhVqKOsmZNky552Cn8/vtXsbt/QeHgEK5SRm508dm60alTRQJBALx5ZTSMhl6vsWLg/G6S/yWxuWfjE+msL2b2SrPsl8mELA8+rJXZLsdEEP+j6zJA4ymdscY3NiUfNGiXh0YZ4lsCQBVe3DxfvQqz9s/ngaa9lGF/OXVGGpjL4Q+7cMiOm9MMqIf972MD/ZMB7slB5A7bH//dHhdgAaybpYseWED6TaECQFObRlnZPIIkTfwe8dvbOXPvMt/yy5KM3zo9Z0YJXgv2pdTdaJHQlf+vIhtFC8BvKFX9ri7PryUogocjMM7YDKECQEfYXH9hrdunb4Ho7SnWzLtqO0APDyRk6PlZofxxhzXV638JBtwCdBk2p0dhWHuhWk3KEh9K4IcEjMbKn2NcPHY=";
	
	public static void main(String[]args) throws IOException, NoSuchAlgorithmException {
		
		FileInputStream fis = new FileInputStream("id_rsa_without_protection");
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		
		int priLength=bis.available();
		System.out.println(priLength);
		byte[]b=new byte[priLength];
		if(priLength>0){
			bis.read(b);
		}
		
		String priString = new String(b);
		System.out.println(priString);
		System.out.println("____________________");
		Pattern compiler=Pattern.compile("BEGIN RSA PRIVATE KEY-----\n(.*)=\n" ,Pattern.MULTILINE|Pattern.DOTALL);
		Matcher matcher=compiler.matcher(priString);
		//System.out.println(matcher.find());
		while(matcher.find()) {
			System.out.println( matcher.group() );
		}
		
		
		//System.out.println(pub);
		//System.out.println(pri);
		final String tmpkey = pub;
        
		final EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(Base64.decode(pri));
		
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_TYPE);
		
		
		
		
	}

}
