package com.xiuye.test;

import com.xiuye.cert.util.CertUtil;

public class CertUtilTestMain {

	
	public static void main(String[] args) {
		
		CertUtil.verifySign("wuming3.cer", "signed.cer");
		System.out.println("verify through,no error and end");
	}

}
