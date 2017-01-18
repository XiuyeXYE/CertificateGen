package com.xiuye.test;

import java.util.Date;
import java.util.List;

import org.junit.Test;

import com.xiuye.cert.DigitalCertificateGenerator;
import com.xiuye.cert.bean.KeyStoreInfo;
import com.xiuye.cert.bean.SignedCertInfo;
import com.xiuye.cert.util.CertUtil;

public class DCGenTest {

	@Test
	public void testGenerateCert() {
		KeyStoreInfo certInfo = new KeyStoreInfo("荆轲2", "123", "456", "1", "2",
				"3", "4", "5", "6", new Date(), 365, "CurrentTest.pfx");
		DigitalCertificateGenerator.generatePFX(certInfo);

		certInfo = new KeyStoreInfo("无名5", "789", "101", "7", "8", "9", "10",
				"11", "12", new Date(), 365, "wuming5.keystore");
		DigitalCertificateGenerator.generateJKS(certInfo);
		certInfo = new KeyStoreInfo("无名3", "789", "101", "7", "8", "9", "10",
				"11", "12", new Date(), 365, "wuming3.keystore");
		DigitalCertificateGenerator.generateJKS(certInfo);
		System.out.println("testGenerateCert end");
	}

	@Test
	public void testAddNewCert() {

		KeyStoreInfo certInfo = new KeyStoreInfo("荆轲6", "123", "456", "1", "2",
				"3", "4", "5", "6", new Date(), 365, "CurrentTest.pfx");
		DigitalCertificateGenerator.addNewCert2PFX(certInfo);

		certInfo = new KeyStoreInfo("无名9", "789", "101", "7", "8", "9", "10",
				"11", "12", new Date(), 365, "CurrentTest.keystore");
		DigitalCertificateGenerator.addNewCert2JKS(certInfo);
		certInfo = new KeyStoreInfo("无名7", "789", "101", "7", "8", "9", "10",
				"11", "12", new Date(), 365, "CurrentTest.keystore");
		DigitalCertificateGenerator.addNewCert2JKS(certInfo);
		System.out.println("testAddNewCert end");
	}

	@Test
	public void testCertAliasesInfo() {

		List<String> list = CertUtil.allAliasesInJKS("CurrentTest.keystore",
				"789");

		System.out.println(list);
		list = CertUtil.allAliasesInPFX("CurrentTest.pfx", "123");

		System.out.println(list);
	}

	@Test
	public void testExportCert() {
		DigitalCertificateGenerator.exportJKSPublicKeyCertificate(
				"CurrentTest.keystore", "789", "无名3", "wuming3.cer");
		DigitalCertificateGenerator.exportPFXPublicKeyCertificate(
				"CurrentTest.pfx", "123", "荆轲2", "jingke2.cer");
	}

	@Test
	public void testSignCert() {
		SignedCertInfo signedCertInfo = new SignedCertInfo();
		String s = "中原";
		signedCertInfo.setC(s);
		signedCertInfo.setCN(s);
		signedCertInfo.setIssuerAlias("无名3");
		signedCertInfo.setIssuerAliasPass("101");
		signedCertInfo.setKeyStorePass("789");
		signedCertInfo.setKeyStorePath("CurrentTest.keystore");
		signedCertInfo.setL(s);
		signedCertInfo.setO(s);
		signedCertInfo.setOU(s);
		signedCertInfo.setST(s);
		signedCertInfo.setSubjectAlias(s);
		signedCertInfo.setSubjectAliasPass(s);
		signedCertInfo.setSubjectPath("signed.cer");
		signedCertInfo.setValidity(365 * 2);

		System.out.println(signedCertInfo);

		DigitalCertificateGenerator.signCertJKSForSubject(signedCertInfo);
	}
	
	
}
