package com.xiuye.test;

import java.util.Date;

import org.junit.Test;

import com.xiuye.cert.DigitalCertificateGenerator;
import com.xiuye.cert.bean.KeyStoreInfo;
import com.xiuye.cert.bean.SignedCertInfo;

public class DCGenTest {

	@Test
	public void testGenerateCert() {// 生成证书库/证书
		// 别名,库密码,证书密码,CN,OU,O,L,ST,C,开始时间,有效期限(单位:天),存储路径
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
	public void testAddNewCert() {// 添加新证书到证书库

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
	public void testExportCert() {// 导出公钥证书cer
		// 证书库路径,库密码,别名,cer证书路径
		DigitalCertificateGenerator.exportJKSPublicKeyCertificate(
				"CurrentTest.keystore", "789", "无名3", "wuming3.cer");
		DigitalCertificateGenerator.exportPFXPublicKeyCertificate(
				"CurrentTest.pfx", "123", "荆轲2", "jingke2.cer");
	}

	@Test
	public void testSignCert() {// 根据根证书签发证书
		// 签发证书的信息
		SignedCertInfo signedCertInfo = new SignedCertInfo();
		String s = "中原";
		signedCertInfo.setC(s);// 签发证书:C
		signedCertInfo.setCN(s);// 签发证书:CN
		signedCertInfo.setIssuerAlias("无名3");// 证书颁发者别名
		signedCertInfo.setIssuerAliasPass("101");// 证书颁发者证书密码
		signedCertInfo.setKeyStorePass("789");// 颁发者的所在证书库
		signedCertInfo.setKeyStorePath("CurrentTest.keystore");// 颁发者证书库路径
		signedCertInfo.setL(s);// 签发证书:L
		signedCertInfo.setO(s);// 签发证书:O
		signedCertInfo.setOU(s);// 签发证书:OU
		signedCertInfo.setST(s);// 签发证书:ST
		signedCertInfo.setSubjectAlias(s);// 使用者证书别名
		signedCertInfo.setSubjectAliasPass(s);// 使用者证书密码
		signedCertInfo.setSubjectPath("signed.cer");// 存储签发证书的路径
		signedCertInfo.setValidity(365 * 2);// 有效期,单位:天

		System.out.println(signedCertInfo);

		// 签发证书("中原"的证书),并且存储到证书库("CurrentTest.keystore")
		DigitalCertificateGenerator.signCertJKSForSubject(signedCertInfo);
	}

}
