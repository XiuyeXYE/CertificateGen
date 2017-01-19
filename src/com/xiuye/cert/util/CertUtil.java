package com.xiuye.cert.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.xiuye.cert.DigitalCertificateGenerator;

public class CertUtil {

	public static byte[] encodeByKeyStorePublicKey(KeyStore ks, String alias,
			byte[] input) {

		try {
			PublicKey pk = ks.getCertificate(alias).getPublicKey();
			return crypt(Cipher.ENCRYPT_MODE, pk, input);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;

	}

	public static byte[] decodeByKeyStorePublicKey(KeyStore ks, String alias,
			byte[] input) {

		try {
			PublicKey pk = ks.getCertificate(alias).getPublicKey();
			return crypt(Cipher.DECRYPT_MODE, pk, input);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;

	}

	public static byte[] decodeByKeyStorePrivateKey(KeyStore ks, String alias,
			String certPass, byte[] input) {
		PrivateKey pk;
		try {
			pk = (PrivateKey) ks.getKey(alias, certPass.toCharArray());
			return crypt(Cipher.DECRYPT_MODE, pk, input);
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;

	}

	public static byte[] encodeByKeyStorePrivateKey(KeyStore ks, String alias,
			String certPass, byte[] input) {
		PrivateKey pk;
		try {
			pk = (PrivateKey) ks.getKey(alias, certPass.toCharArray());
			return crypt(Cipher.ENCRYPT_MODE, pk, input);
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;

	}

	public static byte[] encodeByJKSPublicKey(String storePath,
			String storePass, String alias, byte[] msg) {
		return encodeByKeyStorePublicKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, alias, msg);
	}

	public static byte[] decodeByJKSPublicKey(String storePath,
			String storePass, String alias, byte[] msg) {
		return decodeByKeyStorePublicKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, alias, msg);
	}

	public static byte[] decodeByPFXPublicKey(String storePath,
			String storePass, String alias, byte[] msg) {
		return decodeByKeyStorePublicKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, alias, msg);
	}

	public static byte[] encodeByPFXPublicKey(String storePath,
			String storePass, String alias, byte[] msg) {
		return encodeByKeyStorePublicKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, alias, msg);
	}

	public static byte[] encodeByJKSPrivateKey(String storePath,
			String storePass, String alias, String certPass, byte[] msg) {
		return encodeByKeyStorePrivateKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, alias,
				certPass, msg);
	}

	public static byte[] decodeByJKSPrivateKey(String storePath,
			String storePass, String alias, String certPass, byte[] msg) {
		return decodeByKeyStorePrivateKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, alias,
				certPass, msg);
	}

	public static byte[] decodeByPFXPrivateKey(String storePath,
			String storePass, String alias, String certPass, byte[] msg) {
		return decodeByKeyStorePrivateKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, alias,
				certPass, msg);
	}

	public static byte[] encodeByPFXPrivateKey(String storePath,
			String storePass, String alias, String certPass, byte[] msg) {
		return encodeByKeyStorePrivateKey(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, alias,
				certPass, msg);
	}

	public static byte[] encodeByKeyStorePublicKey(String storePath,
			String storePass, String storeType, String alias, byte[] msg) {
		PublicKey pk = publicKeyInKeyStore(storePath, storePass, storeType,
				alias);
		return crypt(Cipher.ENCRYPT_MODE, pk, msg);
	}

	public static byte[] decodeByKeyStorePublicKey(String storePath,
			String storePass, String storeType, String alias, byte[] msg) {
		PublicKey pk = publicKeyInKeyStore(storePath, storePass, storeType,
				alias);
		return crypt(Cipher.DECRYPT_MODE, pk, msg);
	}

	public static byte[] encodeByKeyStorePrivateKey(String storePath,
			String storePass, String storeType, String alias, String certPass,
			byte[] msg) {

		PrivateKey pk = privateKeyInKeyStore(storePath, storePass, storeType,
				alias, certPass);

		return crypt(Cipher.ENCRYPT_MODE, pk, msg);

	}

	public static byte[] decodeByKeyStorePrivateKey(String storePath,
			String storePass, String storeType, String alias, String certPass,
			byte[] msg) {

		PrivateKey pk = privateKeyInKeyStore(storePath, storePass, storeType,
				alias, certPass);

		return crypt(Cipher.DECRYPT_MODE, pk, msg);

	}

	private static byte[] crypt(int opmode, Key key, byte[] input) {
		Cipher cipher;
		try {
			cipher = Cipher
					.getInstance(DigitalCertificateGenerator.KEY_PAIR_ALGORITHM_RSA);
			cipher.init(opmode, key);
			return cipher.doFinal(input);
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
		return null;

	}

	public static byte[] decodeByCert(String certPath, byte[] msgData) {
		try {

			PublicKey pk = publicKeyInCert(certPath);

			Cipher cipher = Cipher
					.getInstance(DigitalCertificateGenerator.KEY_PAIR_ALGORITHM_RSA);
			cipher.init(Cipher.DECRYPT_MODE, pk);

			byte[] data = cipher.doFinal(msgData);

			return data;

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
		return null;

	}

	public static byte[] encodeByCert(String certPath, byte[] msgData) {
		try {

			PublicKey pk = publicKeyInCert(certPath);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pk);

			byte[] data = cipher.doFinal(msgData);

			return data;

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
		return null;
	}

	public static PublicKey publicKeyInPFX(String storePath, String storePass,
			String alias) {
		return publicKeyInKeyStore(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_PKCS12, alias);
	}

	public static PublicKey publicKeyInJKS(String storePath, String storePass,
			String alias) {
		return publicKeyInKeyStore(storePath, storePass,
				DigitalCertificateGenerator.KEY_STORE_TYPE_JKS, alias);
	}

	public static PublicKey publicKeyInKeyStore(String storePath,
			String storePass, String storeType, String alias) {
		KeyStore ks = keyStoreLoad(storePath, storePass, storeType);
		try {
			return ks.getCertificate(alias).getPublicKey();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

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
