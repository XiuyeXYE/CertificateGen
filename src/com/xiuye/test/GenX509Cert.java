package com.xiuye.test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Vector;

import com.sun.xml.internal.stream.Entity;

import sun.misc.BASE64Encoder;
import sun.security.provider.certpath.X509CertificatePair;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerUniqueIdentity;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.Extension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.UniqueIdentity;
import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class GenX509Cert {
	private SecureRandom sr = new SecureRandom();

	public GenX509Cert() throws NoSuchAlgorithmException,
			NoSuchProviderException {
		sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
	}

	public void createCert(X509Certificate certificate, PrivateKey rootPrivKey,
			KeyPair kp) throws CertificateException, IOException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException {
		byte certbytes[] = certificate.getEncoded();
		X509CertImpl x509certimpl = new X509CertImpl(certbytes);

		X509CertInfo x509certinfo = (X509CertInfo) x509certimpl
				.get("x509.info");

		x509certinfo.set("key", new CertificateX509Key(kp.getPublic()));

		CertificateExtensions certificateextensions = new CertificateExtensions();
		certificateextensions.set(
				"SubjectKeyIdentifier",
				new SubjectKeyIdentifierExtension((new KeyIdentifier(kp
						.getPublic())).getIdentifier()));
		x509certinfo.set("extensions", certificateextensions);

		// 设置issuer域
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
		// 设置序列号域
		CertificateVersion cv = new CertificateVersion(CertificateVersion.V3);
		x509certinfo.set(X509CertInfo.VERSION, cv);
		// 设置版本号 只有v1 ,v2,v3这几个合法值
		/**
		 * 以上是证书的基本信息 如果要添加用户扩展信息 则比较麻烦 首先要确定version必须是v3否则不行 然后按照以下步骤
		 **/
		ObjectIdentifier oid = new ObjectIdentifier(new int[] { 2, 5, 29, 15 });
		// 生成扩展域的id 是个int数组 第1位最大2 第2位最大39 最多可以几位不明....
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
		x509certimpl1.sign(rootPrivKey, "MD5WithRSA");
		// 使用另一个证书的私钥来签名此证书 这里使用 md5散列 用rsa来加密

		BASE64Encoder base64 = new BASE64Encoder();
		FileOutputStream fos = new FileOutputStream(new File("e:\\ScriptX.crt"));
		base64.encodeBuffer(x509certimpl1.getEncoded(), fos);

		try {
			Certificate[] certChain = { x509certimpl1 };
			savePfx("scriptx", kp.getPrivate(), "123456", certChain,
					"e:\\ScriptX.pfx");

			FileInputStream in = new FileInputStream("e:\\ScriptX.pfx");
			KeyStore inputKeyStore = KeyStore.getInstance("pkcs12");
			inputKeyStore.load(in, "123456".toCharArray());

			Certificate cert = inputKeyStore.getCertificate("scriptx");
			System.out.print(cert.getPublicKey());

			PrivateKey privk = (PrivateKey) inputKeyStore.getKey("scriptx",
					"123456".toCharArray());

			FileOutputStream privKfos = new FileOutputStream(new File(
					"e:\\ScriptX.pvk"));

			privKfos.write(privk.getEncoded());
			System.out.print(privk);
			// base64.encode(key.getEncoded(), privKfos);

			in.close();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// 生成文件
		x509certimpl1.verify(certificate.getPublicKey(), null);

	}

	public void savePfx(String alias, PrivateKey privKey, String pwd,
			Certificate[] certChain, String filepath) throws Exception {
		KeyStore outputKeyStore = KeyStore.getInstance("pkcs12");
		System.out.println(outputKeyStore.getType());
		outputKeyStore.load(null, pwd.toCharArray());
		outputKeyStore
				.setKeyEntry(alias, privKey, pwd.toCharArray(), certChain);
		// KeyStore.PrivateKeyEntry pke=new
		// KeyStore.PrivateKeyEntry(kp.getPrivate(),certChain);
		// KeyStore.PasswordProtection password=new
		// KeyStore.PasswordProtection("123456".toCharArray());
		// outputKeyStore.setEntry("scriptx", pke, password);

		FileOutputStream out = new FileOutputStream(filepath);
		outputKeyStore.store(out, pwd.toCharArray());
		out.close();
	}

	public void saveJks(String alias, PrivateKey privKey, String pwd,
			Certificate[] certChain, String filepath) throws Exception {
		KeyStore outputKeyStore = KeyStore.getInstance("jks");
		System.out.println(outputKeyStore.getType());
		outputKeyStore.load(null, pwd.toCharArray());
		outputKeyStore
				.setKeyEntry(alias, privKey, pwd.toCharArray(), certChain);
		// KeyStore.PrivateKeyEntry pke=new
		// KeyStore.PrivateKeyEntry(kp.getPrivate(),certChain);
		// KeyStore.PasswordProtection password=new
		// KeyStore.PasswordProtection("123456".toCharArray());
		// outputKeyStore.setEntry("scriptx", pke, password);

		FileOutputStream out = new FileOutputStream(filepath);
		outputKeyStore.store(out, pwd.toCharArray());
		out.close();
	}

	public void createRootCA() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, IOException,
			CertificateException, SignatureException, UnrecoverableKeyException {
		CertAndKeyGen cak = new CertAndKeyGen("RSA", "MD5WithRSA", null);
		// 参数分别为 公钥算法 签名算法 providername（因为不知道确切的 只好使用null 既使用默认的provider）
		cak.generate(1024);
		cak.setRandom(sr);
		// 生成一对key 参数为key的长度 对于rsa不能小于512
		X500Name subject = new X500Name(
				"CN=RootCA,OU=hackwp,O=wp,L=BJ,S=BJ,C=CN");
		// subject name
		X509Certificate certificate = cak.getSelfCertificate(subject,
				new Date(), 3650 * 24L * 60L * 60L);

		X509Certificate[] certs = { certificate };

		try {
			savePfx("RootCA", cak.getPrivateKey(), "123456", certs,
					"e:\\RootCa.pfx");
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 后一个long型参数代表从现在开始的有效期 单位为秒（如果不想从现在开始算 可以在后面改这个域）
		BASE64Encoder base64 = new BASE64Encoder();
		FileOutputStream fos = new FileOutputStream(new File("e:\\RootCa.crt"));
		base64.encodeBuffer(certificate.getEncoded(), fos);
		// 生成cert文件 base64加密 当然也可以不加密
	}

	public void signCert() throws NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchProviderException, SignatureException {
		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");

			FileInputStream ksfis = new FileInputStream("e:\\RootCa.pfx");
			char[] storePwd = "123456".toCharArray();
			char[] keyPwd = "123456".toCharArray();

			ks.load(ksfis, storePwd);
			ksfis.close();
			// 从密钥仓库得到私钥
			PrivateKey privK = (PrivateKey) ks.getKey("RootCA", keyPwd);

			X509Certificate certificate = (X509Certificate) ks
					.getCertificate("RootCA");

			createCert(certificate, privK, genKey());

		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public KeyPair genKey() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024, sr);
		System.out.print(kpg.getAlgorithm());
		KeyPair kp = kpg.generateKeyPair();

		return kp;
	}

	public static void main(String[] args) {
		try {
			GenX509Cert gcert = new GenX509Cert();
			gcert.createRootCA();
			gcert.signCert();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
