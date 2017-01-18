package com.xiuye.cert.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import com.xiuye.cert.DigitalCertificateGenerator;

public class CertUtil {

	
	
	
	public static PrivateKey privateKeyInJKS(String storePath,
			String storePass, String alias, String certPass) {
		return privateKeyInKeyStore(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, alias, certPass);
	}

	public static PrivateKey privateKeyInPFX(String storePath,
			String storePass, String alias, String certPass) {
		return privateKeyInKeyStore(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, alias,
				certPass);
	}

	public static PrivateKey privateKeyInKeyStore(String storePath,
			String storePass, String storeType, String alias, String certPass) {
		KeyStore ks = keyStoreLoad(storePath, storePass, storeType);
		PrivateKey pk = null;
		try {
			pk = (PrivateKey) ks.getKey(alias, certPass.toCharArray());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return pk;
	}

	public static KeyStore keyStoreLoad(String storePath, String storePass,
			String storeType) {

		FileInputStream fis = null;

		try {
			fis = new FileInputStream(storePath);
			KeyStore ks = KeyStore.getInstance(storeType);
			ks.load(fis, storePass.toCharArray());
			return ks;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return null;
	}

	public static PublicKey publicKeyInCert(String certPath) {

		return cert(certPath).getPublicKey();

	}

	public static List<String> allAliasesInJKS(String storePath,
			String storePass) {
		return allAliasesInKeyStore(storePath,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, storePass);
	}

	public static List<String> allAliasesInPFX(String storePath,
			String storePass) {
		return allAliasesInKeyStore(storePath,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, storePass);
	}

	public static List<String> allAliasesInKeyStore(String storePath,
			String keyStoreType, String storePass) {

		List<String> aliases = new ArrayList<String>();
		File f = new File(storePath);
		FileInputStream fis = null;
		KeyStore outStore;
		try {
			outStore = KeyStore.getInstance(keyStoreType);
			fis = new FileInputStream(f);
			outStore.load(fis, storePass.toCharArray());
			Enumeration<String> e = outStore.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				aliases.add(alias);
			}
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (CertificateException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return aliases;

	}

	public static void verifyValidityDays(String certPath) {

		X509Certificate cert = (X509Certificate) cert(certPath);
		try {
			cert.checkValidity(new Date());
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
		}
	}

	public static void verifySign(String fatherCertPath, String sonCertPath) {

		Certificate son = cert(sonCertPath);
		Certificate father = cert(fatherCertPath);
		try {
			son.verify(father.getPublicKey());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

	}

	public static Certificate cert(String certPath) {
		FileInputStream fis = null;
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			fis = new FileInputStream(certPath);
			return cf.generateCertificate(fis);

		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

}
