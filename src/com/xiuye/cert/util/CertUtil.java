package com.xiuye.cert.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class CertUtil {

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
