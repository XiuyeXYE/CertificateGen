package com.xiuye.test;

import org.junit.Test;

import com.xiuye.cert.util.CertUtil;

public class CertUtilTest {

	@Test
	public void testCertVerifing(){
		
		CertUtil.verifySign("wuming3.cer", "signed.cer");
		System.out.println("test passed!");
	}
	@Test
	public void testCertValidityDays(){
		
		CertUtil.verifyValidityDays("wuming3.cer");
		System.out.println("test passed!");
	}
	
	@Test
	public void testGetAllAliasesInfo(){
		
		System.out.println(CertUtil.allAliasesInJKS("CurrentTest.keystore", "789"));
		System.out.println(CertUtil.allAliasesInPFX("CurrentTest.pfx", "123"));
		
	}

	@Test
	public void testPublicKeyInCert(){
		
		System.out.println(CertUtil.publicKeyInCert("wuming3.cer"));
		
	}
	@Test
	public void testPrivateKey(){
		
		System.out.println(CertUtil.privateKeyInJKS("CurrentTest.keystore", "789", "无名3", "101"));
		System.out.println(CertUtil.privateKeyInPFX("CurrentTest.pfx", "123", "荆轲6", "456"));
		
	}
	
}
