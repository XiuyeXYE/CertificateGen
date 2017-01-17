package com.xiuye.test;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProviderMain {
	
	public static void main(String[] args) {
		
		Security.addProvider(new BouncyCastleProvider());
		
		Provider []ps = Security.getProviders();
		
		for(Provider p : ps){
			System.out.println(p);
		}
		
		System.out.println(KeyStore.getDefaultType());
	}

}
