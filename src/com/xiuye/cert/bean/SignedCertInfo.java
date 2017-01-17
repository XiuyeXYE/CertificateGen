package com.xiuye.cert.bean;


public class SignedCertInfo {

	private String CN;
	private String OU;
	private String O;
	private String L;
	private String ST;
	private String C;

	private String keyStorePath;
	private String keyStorePass;
	private String issuerAlias;
	private String issuerAliasPass;
	private String subjectAlias;
	private String subjectAliasPass;
	private int validity;
	private String subjectPath;
	
	
	public String getCN() {
		return CN;
	}
	public void setCN(String cN) {
		CN = cN;
	}
	public String getOU() {
		return OU;
	}
	public void setOU(String oU) {
		OU = oU;
	}
	public String getO() {
		return O;
	}
	public void setO(String o) {
		O = o;
	}
	public String getL() {
		return L;
	}
	public void setL(String l) {
		L = l;
	}
	public String getST() {
		return ST;
	}
	public void setST(String sT) {
		ST = sT;
	}
	public String getC() {
		return C;
	}
	public void setC(String c) {
		C = c;
	}
	public String getKeyStorePath() {
		return keyStorePath;
	}
	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}
	public String getKeyStorePass() {
		return keyStorePass;
	}
	public void setKeyStorePass(String keyStorePass) {
		this.keyStorePass = keyStorePass;
	}
	public String getIssuerAlias() {
		return issuerAlias;
	}
	public void setIssuerAlias(String issuerAlias) {
		this.issuerAlias = issuerAlias;
	}
	public String getIssuerAliasPass() {
		return issuerAliasPass;
	}
	public void setIssuerAliasPass(String issuerAliasPass) {
		this.issuerAliasPass = issuerAliasPass;
	}
	public String getSubjectAlias() {
		return subjectAlias;
	}
	public void setSubjectAlias(String subjectAlias) {
		this.subjectAlias = subjectAlias;
	}
	public String getSubjectAliasPass() {
		return subjectAliasPass;
	}
	public void setSubjectAliasPass(String subjectAliasPass) {
		this.subjectAliasPass = subjectAliasPass;
	}
	public int getValidity() {
		return validity;
	}
	public void setValidity(int validity) {
		this.validity = validity;
	}
	public String getSubjectPath() {
		return subjectPath;
	}
	public void setSubjectPath(String subjectPath) {
		this.subjectPath = subjectPath;
	}
	@Override
	public String toString() {
		return "SignedCertInfo [CN=" + CN + ", OU=" + OU + ", O=" + O + ", L="
				+ L + ", ST=" + ST + ", C=" + C + ", keyStorePath="
				+ keyStorePath + ", keyStorePass=" + keyStorePass
				+ ", issuerAlias=" + issuerAlias + ", issuerAliasPass="
				+ issuerAliasPass + ", subjectAlias=" + subjectAlias
				+ ", subjectAliasPass=" + subjectAliasPass + ", validity="
				+ validity + ", subjectPath=" + subjectPath + "]";
	}
	

	
	
}
