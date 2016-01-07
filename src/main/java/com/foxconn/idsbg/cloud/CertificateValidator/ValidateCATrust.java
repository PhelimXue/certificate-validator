package com.foxconn.idsbg.cloud.CertificateValidator;

import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ValidateCATrust {

	public static void main(String[] args) throws Exception {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    FileInputStream clientCrt = new FileInputStream("src/file/client.crt");
	    Certificate cc = cf.generateCertificate(clientCrt);
	    System.out.println(cc);
	    
	    FileInputStream rootCrt = new FileInputStream("src/file/rootCA.crt");
	    Certificate rca = cf.generateCertificate(rootCrt);
	    System.out.println(rca);
	    
	    List<Certificate> mylist = new ArrayList<Certificate>();
	    mylist.add(cc);
	    CertPath cp = cf.generateCertPath(mylist);

	    /* 
	     * 驗證基準
	     * (Anchor)RootCA 可驗證 PublicCA
	     * (Anchor)PublicCA 可驗證 Certificate
	     */
	    TrustAnchor anchor = new TrustAnchor((X509Certificate) rca, null);
	    PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
	    params.setRevocationEnabled(false);
	    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
	    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
	    //印的出來就是對了
	    System.out.println(result);
	}
}
