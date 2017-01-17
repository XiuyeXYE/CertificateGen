package com.xiuye.cert;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.xiuye.cert.bean.CertInfo;

public class CertGenerator{

	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void generateCet(){
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			
			
			
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	public static void generateCert(CertInfo info) {

		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(info.certAlgorithm);
			kpg.initialize(info.keySize);
			KeyPair keyPair = kpg.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			certGen.setSerialNumber(info.serialNumber);
			certGen.setIssuerDN(info.issuer);
			certGen.setNotBefore(info.firstData);
			certGen.setNotAfter(info.lastDate);
			certGen.setSubjectDN(info.subject);
			certGen.setPublicKey(publicKey);
			certGen.setSignatureAlgorithm(info.signatureAlgorithm);
			X509Certificate cert = certGen.generateX509Certificate(privateKey);
			KeyStore keyStore = KeyStore.getInstance(info.keyStoreType);
			
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}
}
