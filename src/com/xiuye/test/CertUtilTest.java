package com.xiuye.test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.xiuye.cert.util.CertUtil;

public class CertUtilTest {

	@Test
	public void testCertVerifing() {

		CertUtil.verifySign("wuming3.cer", "signed.cer");
		System.out.println("test passed!");
	}

	@Test
	public void testCertValidityDays() {

		CertUtil.verifyValidityDays("wuming3.cer");
		System.out.println("test passed!");
	}

	@Test
	public void testGetAllAliasesInfo() {

		System.out.println(CertUtil.allAliasesInJKS("CurrentTest.keystore",
				"789"));
		System.out.println(CertUtil.allAliasesInPFX("CurrentTest.pfx", "123"));

	}

	@Test
	public void testPublicKeyInCert() {

		System.out.println(CertUtil.publicKeyInCert("wuming3.cer"));

		System.out.println("1 := "
				+ CertUtil.publicKeyInJKS("CurrentTest.keystore", "789", "无名3"));
		System.out.println("2 := "
				+ CertUtil.publicKeyInPFX("CurrentTest.pfx", "123", "荆轲6"));

	}

	@Test
	public void testPrivateKey() {

		System.out.println(CertUtil.privateKeyInJKS("CurrentTest.keystore",
				"789", "无名3", "101"));
		System.out.println(CertUtil.privateKeyInPFX("CurrentTest.pfx", "123",
				"荆轲6", "456"));

	}

	@Test
	public void testKeyStoreEncodeAndDecode() {
		String msg = "你好啊,奔跑者!";
		byte[] data = CertUtil.encodeByJKSPrivateKey("CurrentTest.keystore",
				"789", "无名3", "101", msg.getBytes());
		System.out.println(new String(data));
		data = CertUtil.decodeByJKSPublicKey("CurrentTest.keystore", "789",
				"无名3",  data);
		System.out.println(new String(data));
		System.out.println("==============");
		data = CertUtil.encodeByJKSPublicKey("CurrentTest.keystore", "789",
				"无名3",  msg.getBytes());
		System.out.println(new String(data));
		data = CertUtil.decodeByJKSPrivateKey("CurrentTest.keystore", "789",
				"无名3", "101", data);
		System.out.println(new String(data));
		System.out.println("==============");
		data = CertUtil.encodeByPFXPublicKey("CurrentTest.pfx", "123", "荆轲6",
				 msg.getBytes());
		System.out.println(new String(data));
		data = CertUtil.decodeByPFXPrivateKey("CurrentTest.pfx", "123", "荆轲6",
				"456", data);
		System.out.println(new String(data));
		System.out.println("==============");
		data = CertUtil.encodeByPFXPublicKey("CurrentTest.pfx", "123", "荆轲6",
				 msg.getBytes());
		System.out.println(new String(data));
		data = CertUtil.decodeByPFXPrivateKey("CurrentTest.pfx", "123", "荆轲6",
				"456", data);
		System.out.println(new String(data));
	}

	@Test
	public void testEncodeAndDecode() {

		try {
			PublicKey publicKey1 = CertUtil.publicKeyInJKS(
					"CurrentTest.keystore", "789", "无名3");
			PublicKey publicKey2 = CertUtil.publicKeyInPFX("CurrentTest.pfx",
					"123", "荆轲6");

			PrivateKey privateKey1 = CertUtil.privateKeyInJKS(
					"CurrentTest.keystore", "789", "无名3", "101");
			PrivateKey privateKey2 = CertUtil.privateKeyInPFX(
					"CurrentTest.pfx", "123", "荆轲6", "456");

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey1);

			String s = "你好啊,奔跑者!";

			byte[] data = cipher.doFinal(s.getBytes());
			System.out.println("encode s := " + new String(data));

			cipher.init(Cipher.DECRYPT_MODE, publicKey1);

			data = cipher.doFinal(data);
			System.out.println("code s := " + new String(data));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

	}

}
