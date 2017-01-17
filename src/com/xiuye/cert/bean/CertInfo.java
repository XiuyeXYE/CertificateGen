package com.xiuye.cert.bean;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class CertInfo {

	public AlgorithmParameterSpec keySize;
	public String certAlgorithm = "jks";
	public String keyStoreType;
	public BigInteger serialNumber;
	public Date firstData;
	public Date lastDate;
	public X500Principal issuer;
	public X500Principal subject;
	public String signatureAlgorithm;

	
	
}
