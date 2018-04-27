package com.xiuye.test;

import org.junit.Test;

import com.xiuye.cert.util.CertUtil;

public class CertUtilTest {

	@Test
	public void testCertVerifing() {// 验证签发证书的签名

		// "wuming3.cer"是根证书导出的公钥证书,"signed.cer"是签发的子证书.
		CertUtil.verifySign("wuming3.cer", "signed.cer");
		System.out.println("test passed!");
	}

	@Test
	public void testCertValidityDays() {// 验证有效期,即证书没有过期,到当前时间有效.

		CertUtil.verifyValidityDays("wuming3.cer");
		System.out.println("test passed!");
	}

	@Test
	public void testGetAllAliasesInfo() {// 获取证书库中所有证书别名

		System.out.println(CertUtil.allAliasesInJKS("CurrentTest.keystore",
				"789"));
		System.out.println(CertUtil.allAliasesInPFX("CurrentTest.pfx", "123"));

	}

	@Test
	public void testPublicKeyInCert() {// 获取cer证书的公钥

		System.out.println(CertUtil.publicKeyInCert("wuming3.cer"));

		System.out
				.println("1 := "
						+ CertUtil.publicKeyInJKS("CurrentTest.keystore",
								"789", "无名3"));
		System.out.println("2 := "
				+ CertUtil.publicKeyInPFX("CurrentTest.pfx", "123", "荆轲6"));

	}

	@Test
	public void testPrivateKey() {// 根据证书别名,获取证书库中该证书的私钥

		// 证书库路径,证书库密码,证书别名,证书密码
		System.out.println(CertUtil.privateKeyInJKS("CurrentTest.keystore",
				"789", "无名3", "101"));
		System.out.println(CertUtil.privateKeyInPFX("CurrentTest.pfx", "123",
				"荆轲6", "456"));

	}

	@Test
	public void testKeyStoreEncodeAndDecode() {// 根据证书库中的证书(私钥公钥),加密解密
		String msg = "你好啊,奔跑者!";
		// 用私钥加密
		byte[] data = CertUtil.encodeByJKSPrivateKey("CurrentTest.keystore",
				"789", "无名3", "101", msg.getBytes());
		System.out.println(new String(data));
		// 用公钥解密
		data = CertUtil.decodeByJKSPublicKey("CurrentTest.keystore", "789",
				"无名3", data);
		System.out.println(new String(data));

		System.out.println("==============");
		data = CertUtil.encodeByJKSPublicKey("CurrentTest.keystore", "789",
				"无名3", msg.getBytes());
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
	public void testCerFileEncodeAndDecode() {// 公钥证书cer的加密解密

		String msg = "[无名9, 无名7, 中原, 无名3]";
		// cer证书加密
		byte[] encodeBytes = CertUtil
				.encodeByCert("signed.cer", msg.getBytes());

		System.out.println(new String(encodeBytes));
		// 用其相关的私钥解密
		byte[] decodeBytes = CertUtil.decodeByJKSPrivateKey(
				"CurrentTest.keystore", "789", "中原", "中原", encodeBytes);

		System.out.println(new String(decodeBytes));

		System.out.println("=============================");
		// 用其相关的私钥加密
		encodeBytes = CertUtil.encodeByJKSPrivateKey("CurrentTest.keystore",
				"789", "中原", "中原", msg.getBytes());

		System.out.println(new String(encodeBytes));
		// cer证书解密
		decodeBytes = CertUtil.decodeByCert("signed.cer", encodeBytes);

		System.out.println(new String(decodeBytes));

	}

}
