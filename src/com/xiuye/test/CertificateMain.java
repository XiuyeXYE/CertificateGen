package com.xiuye.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.Extension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertificateMain {

	public static void main(String[] args) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, IOException,
			CertificateException, SignatureException, KeyStoreException,
			UnrecoverableKeyException {

		pfx();
		jks();

		KeyStore store = KeyStore.getInstance("pkcs12");
		FileInputStream in = new FileInputStream("test.pfx");
		store.load(in, "123456".toCharArray());
		in.close();
		System.out.println("type := " + store.getType());
		PrivateKey pk = (PrivateKey) store.getKey("xiuye",
				"123456".toCharArray());
		X509Certificate certificate = (X509Certificate) store
				.getCertificate("xiuye");
		byte[] encodeBytes = certificate.getEncoded();

		
		
		X509CertImpl x509certimpl = new X509CertImpl(encodeBytes);
		
		FileOutputStream out = new FileOutputStream("test12.cer");
		out.write(x509certimpl.getEncoded());
		
//		System.out.println("x509certimpl := " + x509certimpl);
		X509CertInfo x509certinfo = (X509CertInfo) x509certimpl
				.get("x509.info");
//		System.out.println("x509certinfo := " + x509certinfo);

		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048, sr);
		KeyPair kp = kpg.genKeyPair();

		x509certinfo.set("key", new CertificateX509Key(kp.getPublic()));

		CertificateExtensions certificateExtensions = new CertificateExtensions();

		certificateExtensions.set(
				"SubjectKeyIdentifier",
				new SubjectKeyIdentifierExtension((new KeyIdentifier(kp
						.getPublic())).getIdentifier()));

		x509certinfo.set("extensions", certificateExtensions);

		X500Name issuer = new X500Name(
				"CN=RootCA,OU=hackwp,O=wp,L=BJ,S=BJ,C=CN");
		x509certinfo.set("issuer.dname", issuer);
		X500Name subject = new X500Name(
				"CN=scriptx, OU=wps, O=wps, L=BJ, ST=BJ, C=CN");
		x509certinfo.set("subject.dname", subject);

		Signature signature = Signature.getInstance("MD5WithRSA");
		signature.initSign(kp.getPrivate());
		X500Signer signer = new X500Signer(signature, issuer);

		AlgorithmId algorithmid = signer.getAlgorithmId();
		x509certinfo
				.set("algorithmID", new CertificateAlgorithmId(algorithmid));

		Date bdate = new Date();
		Date edate = new Date();
		// 天 小时 分 秒 毫秒
		edate.setTime(bdate.getTime() + 3650 * 24L * 60L * 60L * 1000L);
		// validity为有效时间长度 单位为秒
		CertificateValidity certificatevalidity = new CertificateValidity(
				bdate, edate);
		x509certinfo.set("validity", certificatevalidity);
		// 设置有效期域（包含开始时间和到期时间）域名等同与x509certinfo.VALIDITY
		x509certinfo.set("serialNumber", new CertificateSerialNumber(
				(int) (new Date().getTime() / 1000L)));
		// 设置序列号域 // 设置版本号 只有v1 ,v2,v3这几个合法值
		CertificateVersion cv = new CertificateVersion(CertificateVersion.V3);
		x509certinfo.set(X509CertInfo.VERSION, cv);
		/**
		 * 以上是证书的基本信息 如果要添加用户扩展信息 则比较麻烦 首先要确定version必须是v3否则不行 然后按照以下步骤 生成扩展域的id
		 * 是个int数组 第1位最大2 第2位最大39 最多可以几位不明....
		 */
		ObjectIdentifier oid = new ObjectIdentifier(new int[] { 2, 5, 29, 15 });

		String userData = "Digital Signature, Non-Repudiation, Key Encipherment, Data Encipherment (f0)";
		byte l = (byte) userData.length();// 数据总长17位
		byte f = 0x04;
		byte[] bs = new byte[userData.length() + 2];
		bs[0] = f;
		bs[1] = l;
		for (int i = 2; i < bs.length; i++) {
			bs[i] = (byte) userData.charAt(i - 2);
		}
		Extension ext = new Extension(oid, true, bs);
		// 生成一个extension对象 参数分别为 oid，是否关键扩展，byte[]型的内容值
		// 其中内容的格式比较怪异 第一位是flag 这里取4暂时没出错 估计用来说明数据的用处的 第2位是后面的实际数据的长度，然后就是数据
		// 密钥用法
		KeyUsageExtension keyUsage = new KeyUsageExtension();
		keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
		keyUsage.set(KeyUsageExtension.NON_REPUDIATION, true);
		keyUsage.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);
		keyUsage.set(KeyUsageExtension.DATA_ENCIPHERMENT, true);

		// 增强密钥用法
		ObjectIdentifier ekeyOid = new ObjectIdentifier(new int[] { 1, 3, 6, 1,
				5, 5, 7, 3, 3 });
		Vector<ObjectIdentifier> vkeyOid = new Vector<ObjectIdentifier>();
		vkeyOid.add(ekeyOid);
		ExtendedKeyUsageExtension exKeyUsage = new ExtendedKeyUsageExtension(
				vkeyOid);

		CertificateExtensions exts = new CertificateExtensions();

		exts.set("keyUsage", keyUsage);
		exts.set("extendedKeyUsage", exKeyUsage);

		// 如果有多个extension则都放入CertificateExtensions 类中，
		x509certinfo.set(X509CertInfo.EXTENSIONS, exts);
		// 设置extensions域

		X509CertImpl x509certimpl1 = new X509CertImpl(x509certinfo);
		x509certimpl1.sign(kp.getPrivate(), "MD5WithRSA");
		
		FileOutputStream fos = new FileOutputStream(new File("test.cer"));
		
		fos.write(x509certimpl1.getEncoded());
		
		
		

		SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG", "SUN");
		System.out.println(sr1.nextInt());
		CertAndKeyGen cakg1 = new CertAndKeyGen("RSA", "sha256WithRSA");
		cakg1.setRandom(sr1);
		cakg1.generate(2048);

		System.out.println(cakg1);

	}

	public static void pfx() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, IOException,
			CertificateException, SignatureException, KeyStoreException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		// CertAndKeyGen cakg = new CertAndKeyGen("RSA", "MD5WithRSA");
		CertAndKeyGen cakg = new CertAndKeyGen("RSA", "sha256WithRSA");
		cakg.setRandom(sr);
		cakg.generate(2048);
		X500Name subject = new X500Name(
				"CN=RootCA,OU=hackwp,O=wp,L=BJ,ST=BJ,C=CN");

		X509Certificate certificate = cakg.getSelfCertificate(subject,
				new Date(), 3650 * 24L * 60L * 60L);

		KeyStore outStore = KeyStore.getInstance("pkcs12");
		outStore.load(null, "123456".toCharArray());
		outStore.setKeyEntry("xiuye", cakg.getPrivateKey(),
				"123456".toCharArray(), new Certificate[] { certificate });
		FileOutputStream out = new FileOutputStream("test.pfx");
		outStore.store(out, "123456".toCharArray());
		out.close();
		System.out.println("pkcs12");
	}

	public static void jks() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, IOException,
			CertificateException, SignatureException, KeyStoreException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		CertAndKeyGen cakg = new CertAndKeyGen("RSA", "MD5WithRSA");
		cakg.setRandom(sr);
		cakg.generate(2048);
		X500Name subject = new X500Name(
				"CN=RootCA,OU=hackwp,O=wp,L=BJ,S=BJ,C=CN");

		X509Certificate certificate = cakg.getSelfCertificate(subject,
				new Date(), 3650 * 24L * 60L * 60L);

		KeyStore outStore = KeyStore.getInstance("jks");
		outStore.load(null, "123456".toCharArray());
		outStore.setKeyEntry("xiuye", cakg.getPrivateKey(),
				"123456".toCharArray(), new Certificate[] { certificate });

		FileOutputStream out = new FileOutputStream("test.jks");
		outStore.store(out, "123456".toCharArray());
		out.close();
		System.out.println("jks");
	}

}
