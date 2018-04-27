package com.xiuye.cert;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import com.xiuye.cert.bean.KeyStoreInfo;
import com.xiuye.cert.bean.SignedCertInfo;

import sun.security.x509.AlgorithmId;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class DigitalCertificateGenerator {

	public static final String KEY_STORE_TYPE_JKS = "jks";
	public static final String KEY_STORE_TYPE_PKCS12 = "pkcs12";
	public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
	public static final String SECURE_RANDOM_PROVIDER = "SUN";
	public static final String SIGN_ALGORITHM_SHA256 = "sha256WithRSA";
	public static final String SIGN_ALGORITHM_MD5 = "MD5WithRSA";
	public static final String KEY_PAIR_ALGORITHM_RSA = "RSA";

	public static void signCertPFXForSubject(SignedCertInfo signedCertInfo) {
		try {
			X500Name subject = new X500Name("CN=" + signedCertInfo.getCN()
					+ ",OU=" + signedCertInfo.getOU() + ",O="
					+ signedCertInfo.getO() + ",L=" + signedCertInfo.getL()
					+ ",ST=" + signedCertInfo.getST() + ",C="
					+ signedCertInfo.getC());

			issueSignedCert(signedCertInfo.getKeyStorePath(),
					signedCertInfo.getKeyStorePass(), KEY_STORE_TYPE_PKCS12,
					signedCertInfo.getIssuerAlias(),
					signedCertInfo.getIssuerAliasPass(),
					signedCertInfo.getSubjectAlias(),
					signedCertInfo.getSubjectAliasPass(), subject,
					signedCertInfo.getValidity(),
					signedCertInfo.getSubjectPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void signCertJKSForSubject(SignedCertInfo signedCertInfo) {
		try {
			X500Name subject = new X500Name("CN=" + signedCertInfo.getCN()
					+ ",OU=" + signedCertInfo.getOU() + ",O="
					+ signedCertInfo.getO() + ",L=" + signedCertInfo.getL()
					+ ",ST=" + signedCertInfo.getST() + ",C="
					+ signedCertInfo.getC());

			issueSignedCert(signedCertInfo.getKeyStorePath(),
					signedCertInfo.getKeyStorePass(), KEY_STORE_TYPE_JKS,
					signedCertInfo.getIssuerAlias(),
					signedCertInfo.getIssuerAliasPass(),
					signedCertInfo.getSubjectAlias(),
					signedCertInfo.getSubjectAliasPass(), subject,
					signedCertInfo.getValidity(),
					signedCertInfo.getSubjectPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void issueSignedCert(String keyStorePath,
			String keyStorePass, String keyStoreType, String issuerAlias,
			String issuerAliasPass, String subjectAlias,
			String subjectAliasPass, X500Name subject, int validity,
			String subjectPath) {

		FileOutputStream fos = null;
		FileOutputStream keyStoreFos = null;

		FileInputStream fis = null;

		try {
			fis = new FileInputStream(keyStorePath);
			KeyStore ks = KeyStore.getInstance(keyStoreType);
			ks.load(fis, keyStorePass.toCharArray());

			X509Certificate issuerCert = (X509Certificate) ks
					.getCertificate(issuerAlias);
			X509CertImpl issuerCertImpl = new X509CertImpl(
					issuerCert.getEncoded());
			X509CertInfo issuerCertInfo = (X509CertInfo) issuerCertImpl
					.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

			X500Name issuer = (X500Name) issuerCertInfo
					.get(X509CertInfo.SUBJECT + "."
							+ CertificateIssuerName.DN_NAME);
			PrivateKey pk = (PrivateKey) ks.getKey(issuerAlias,
					issuerAliasPass.toCharArray());

			CertAndKeyGen cakg = new CertAndKeyGen(KEY_PAIR_ALGORITHM_RSA,
					SIGN_ALGORITHM_SHA256);
			SecureRandom sr = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM,
					SECURE_RANDOM_PROVIDER);
			cakg.setRandom(sr);
			cakg.generate(2048);

			X509CertInfo info = new X509CertInfo();
			info.set(X509CertInfo.VERSION, new CertificateVersion(
					CertificateVersion.V3));
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
					new Random().nextInt() & 0x7fffffff));

			AlgorithmId aid = AlgorithmId.get(SIGN_ALGORITHM_SHA256);
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(aid));
			info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
			info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
			info.set(X509CertInfo.KEY,
					new CertificateX509Key(cakg.getPublicKey()));
			Date fistDate = new Date();
			Date lastDate = new Date();
			lastDate.setTime(fistDate.getTime()
					+ (validity * 24L * 60L * 60L * 1000));
			CertificateValidity interval = new CertificateValidity(fistDate,
					lastDate);
			info.set(X509CertInfo.VALIDITY, interval);

			X509CertImpl cert = new X509CertImpl(info);

			cert.sign(pk, SIGN_ALGORITHM_SHA256);

			X509Certificate subjectCert = cert;

			X509Certificate[] chain = new X509Certificate[] { subjectCert,
					issuerCert };

			ks.setKeyEntry(subjectAlias, cakg.getPrivateKey(),
					subjectAliasPass.toCharArray(), chain);

			keyStoreFos = new FileOutputStream(keyStorePath);

			ks.store(keyStoreFos, keyStorePass.toCharArray());

			fos = new FileOutputStream(subjectPath);

			fos.write(cert.getEncoded());
			fos.flush();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		finally {
			try {
				if (fos != null) {
					fos.close();
				}
				if (fis != null) {
					fis.close();
				}
				if (keyStoreFos != null) {
					keyStoreFos.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static void exportPFXPublicKeyCertificate(
			String keyStorePathAndFileName, String keyStorePass, String alias,
			String exportPathAndFileName) {

		exportPublicKeyCertificate(keyStorePathAndFileName, keyStorePass,
				KEY_STORE_TYPE_PKCS12, alias, exportPathAndFileName);

	}

	public static void exportJKSPublicKeyCertificate(
			String keyStorePathAndFileName, String keyStorePass, String alias,
			String exportPathAndFileName) {

		exportPublicKeyCertificate(keyStorePathAndFileName, keyStorePass,
				KEY_STORE_TYPE_JKS, alias, exportPathAndFileName);

	}

	public static void exportPublicKeyCertificate(
			String keyStorePathAndFileName, String keyStorePass,
			String keyStoreType, String alias, String exportPathAndFileName) {
		FileOutputStream fos = null;
		FileInputStream fis = null;
		try {
			KeyStore ks = KeyStore.getInstance(keyStoreType);
			fis = new FileInputStream(keyStorePathAndFileName);
			ks.load(fis, keyStorePass.toCharArray());
			Certificate cert = ks.getCertificate(alias);
			fos = new FileOutputStream(exportPathAndFileName);
			fos.write(cert.getEncoded());
			fos.flush();

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (fos != null) {
					fos.close();
				}
				if (fis != null) {
					fis.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static void generatePFX(String alias, String keyStorePass,
			String certPass, String CN, String OU, String O, String L,
			String ST, String C, Date start, long validityDays,
			String pathAndFileName) {
		generateDigitalCert(KEY_STORE_TYPE_PKCS12, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, alias, keyStorePass, certPass, CN, OU,
				O, L, ST, C, start, validityDays, pathAndFileName, true);

	}

	public static void addNewCert2PFX(String alias, String keyStorePass,
			String certPass, String CN, String OU, String O, String L,
			String ST, String C, Date start, long validityDays,
			String pathAndFileName) {
		generateDigitalCert(KEY_STORE_TYPE_PKCS12, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, alias, keyStorePass, certPass, CN, OU,
				O, L, ST, C, start, validityDays, pathAndFileName, false);

	}

	public static void addNewCert2PFX(KeyStoreInfo certInfo) {
		generateDigitalCert(KEY_STORE_TYPE_PKCS12, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, certInfo.getAlias(),
				certInfo.getKeyStorePass(), certInfo.getCertPass(),
				certInfo.getCN(), certInfo.getOU(), certInfo.getO(),
				certInfo.getL(), certInfo.getST(), certInfo.getC(),
				certInfo.getStart(), certInfo.getValidityDays(),
				certInfo.getPathAndFileName(), false);
	}

	public static void generatePFX(KeyStoreInfo certInfo) {
		generateDigitalCert(KEY_STORE_TYPE_PKCS12, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, certInfo.getAlias(),
				certInfo.getKeyStorePass(), certInfo.getCertPass(),
				certInfo.getCN(), certInfo.getOU(), certInfo.getO(),
				certInfo.getL(), certInfo.getST(), certInfo.getC(),
				certInfo.getStart(), certInfo.getValidityDays(),
				certInfo.getPathAndFileName(), true);
	}

	public static void generateJKS(String alias, String keyStorePass,
			String certPass, String CN, String OU, String O, String L,
			String ST, String C, Date start, long validityDays,
			String pathAndFileName) {
		generateDigitalCert(KEY_STORE_TYPE_JKS, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, alias, keyStorePass, certPass, CN, OU,
				O, L, ST, C, start, validityDays, pathAndFileName, true);
	}

	public static void addNewCert2JKS(String alias, String keyStorePass,
			String certPass, String CN, String OU, String O, String L,
			String ST, String C, Date start, long validityDays,
			String pathAndFileName) {
		generateDigitalCert(KEY_STORE_TYPE_JKS, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, alias, keyStorePass, certPass, CN, OU,
				O, L, ST, C, start, validityDays, pathAndFileName, false);
	}

	public static void generateJKS(KeyStoreInfo certInfo) {
		generateDigitalCert(KEY_STORE_TYPE_JKS, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, certInfo.getAlias(),
				certInfo.getKeyStorePass(), certInfo.getCertPass(),
				certInfo.getCN(), certInfo.getOU(), certInfo.getO(),
				certInfo.getL(), certInfo.getST(), certInfo.getC(),
				certInfo.getStart(), certInfo.getValidityDays(),
				certInfo.getPathAndFileName(), true);
	}

	public static void addNewCert2JKS(KeyStoreInfo certInfo) {
		generateDigitalCert(KEY_STORE_TYPE_JKS, SIGN_ALGORITHM_SHA256,
				KEY_PAIR_ALGORITHM_RSA, SECURE_RANDOM_ALGORITHM,
				SECURE_RANDOM_PROVIDER, certInfo.getAlias(),
				certInfo.getKeyStorePass(), certInfo.getCertPass(),
				certInfo.getCN(), certInfo.getOU(), certInfo.getO(),
				certInfo.getL(), certInfo.getST(), certInfo.getC(),
				certInfo.getStart(), certInfo.getValidityDays(),
				certInfo.getPathAndFileName(), false);
	}

	public static void generateDigitalCert(String keyStoreType,
			String signAlgorithm, String keyPairAlgorithm,
			String secureRandomAlgorithm, String secureRandomProvider,
			String alias, String keyStorePass, String certPass, String CN,
			String OU, String O, String L, String ST, String C, Date start,
			long validityDays, String pathAndFileName, boolean createNew) {
		FileOutputStream out = null;
		try {
			SecureRandom sr = SecureRandom.getInstance(secureRandomAlgorithm,
					secureRandomProvider);
			CertAndKeyGen cakg = new CertAndKeyGen(keyPairAlgorithm,
					signAlgorithm);
			cakg.setRandom(sr);
			cakg.generate(2048);
			X500Name subject = new X500Name("CN=" + CN + ",OU=" + OU + ",O="
					+ O + ",L=" + L + ",ST=" + ST + ",C=" + C);

			X509Certificate certificate = cakg.getSelfCertificate(subject,
					start, validityDays * 24L * 60L * 60L);
			KeyStore outStore = KeyStore.getInstance(keyStoreType);
			if (createNew) {
				outStore.load(null, keyStorePass.toCharArray());
				outStore.setKeyEntry(alias, cakg.getPrivateKey(),
						certPass.toCharArray(),
						new Certificate[] { certificate });
			} else {
				File f = new File(pathAndFileName);
				if (!f.exists()) {
					throw new FileNotFoundException("证书库文件不存在,不能把新的证书加入到证书库.");
				}

				FileInputStream fis = new FileInputStream(f);
				outStore.load(fis, keyStorePass.toCharArray());
				fis.close();
				outStore.setKeyEntry(alias, cakg.getPrivateKey(),
						certPass.toCharArray(),
						new Certificate[] { certificate });

			}
			out = new FileOutputStream(pathAndFileName);
			outStore.store(out, keyStorePass.toCharArray());

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} finally {

			try {
				if (out != null) {
					out.close();
					out = null;
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

}
