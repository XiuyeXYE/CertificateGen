package com.xiuye.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import com.xiuye.cert.DigitalCertificateGenerator;
import com.xiuye.cert.bean.KeyStoreInfo;
import com.xiuye.cert.bean.SignedCertInfo;
import com.xiuye.cert.util.CertUtil;

public class DigitalCertificateGeneratorMain {

	public static void main(String[] args) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException, InvalidKeyException,
			NoSuchProviderException, SignatureException {

//		KeyStoreInfo certInfo = new KeyStoreInfo("荆轲2", "123", "456", "1", "2",
//				"3", "4", "5", "6", new Date(), 365, "CurrentTest.pfx");
//		DigitalCertificateGenerator.generatePFX(certInfo);
//		DigitalCertificateGenerator.addNewCert2PFX(certInfo);
//
//		certInfo = new KeyStoreInfo("无名5", "789", "101", "7", "8", "9", "10",
//				"11", "12", new Date(), 365, "CurrentTest.keystore");
//		DigitalCertificateGenerator.generateJKS(certInfo);
//		DigitalCertificateGenerator.addNewCert2JKS(certInfo);
//		certInfo = new KeyStoreInfo("无名3", "789", "101", "7", "8", "9", "10",
//				"11", "12", new Date(), 365, "CurrentTest.keystore");
//		DigitalCertificateGenerator.generateJKS(certInfo);
//		DigitalCertificateGenerator.addNewCert2JKS(certInfo);
//
//		File f = new File("CurrentTest.keystore");
//		if (!f.exists()) {
//			System.out.println("not exist!");
//		}
//		KeyStore outStore = KeyStore.getInstance("jks");
//		FileInputStream fis = new FileInputStream(f);
//		outStore.load(fis, "789".toCharArray());
//
//		Enumeration<String> e = outStore.aliases();
//
//		// while(e.hasMoreElements()){
//		// String alias = e.nextElement();
//
//		Key key = outStore.getKey("中原", "中原".toCharArray());
//
//		System.out.println("===========================");
//		System.out.println(" key := " + key);
//		System.out.println("===========================");
//
//		key = outStore.getKey("无名3", "101".toCharArray());
//
//		System.out.println("===========================");
//		System.out.println(" key := " + key);
//		System.out.println("===========================");
//
//		// }
//		//
//		DigitalCertificateGenerator.exportJKSPublicKeyCertificate(
//				"CurrentTest.keystore", "789", "无名3", "wuming3.cer");
//		DigitalCertificateGenerator.exportPFXPublicKeyCertificate(
//				"CurrentTest.pfx", "123", "荆轲2", "jingke2.cer");
//		SignedCertInfo signedCertInfo = new SignedCertInfo();
//		String s = "中原";
//		signedCertInfo.setC(s);
//		signedCertInfo.setCN(s);
//		signedCertInfo.setIssuerAlias("无名3");
//		signedCertInfo.setIssuerAliasPass("101");
//		signedCertInfo.setKeyStorePass("789");
//		signedCertInfo.setKeyStorePath("CurrentTest.keystore");
//		signedCertInfo.setL(s);
//		signedCertInfo.setO(s);
//		signedCertInfo.setOU(s);
//		signedCertInfo.setST(s);
//		signedCertInfo.setSubjectAlias(s);
//		signedCertInfo.setSubjectAliasPass(s);
//		signedCertInfo.setSubjectPath("signed.cer");
//		signedCertInfo.setValidity(365);
//
//		System.out.println(signedCertInfo.getKeyStorePath());
//
//		DigitalCertificateGenerator.signCertJKSForSubject(signedCertInfo);
//
//		Certificate c1 = CertUtil.cert("wuming3.cer");
//		Certificate c = CertUtil.cert("signed.cer");
//		c.verify(c1.getPublicKey());
//		System.out.println(c);
//		System.out.println("end");

	}

}
