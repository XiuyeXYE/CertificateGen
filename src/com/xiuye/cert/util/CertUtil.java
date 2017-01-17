package com.xiuye.cert.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertUtil {

	public static void verifyValidity(String certPath) {

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
