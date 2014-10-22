package com.johnkuper.epam.main;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher {

	final static Logger logger = LoggerFactory.getLogger("JohnKuper");
	private final static String URL = "https://localhost:8443/HelloWorld";
	private final static String CLIENT_KEYSTORE_PATH = "src/main/resources/client.jks";
	private final static String CLIENT_TRUSTSTORE_PATH = "src/main/resources/clienttrust.jks";
	private final static char[] storePass = "password".toCharArray();
	private final static char[] keyPass = "password".toCharArray();

	public static void main(String[] args) {

		try {

			TwoWayAuthenticationConnector connector = new TwoWayAuthenticationConnector();
			HttpsURLConnection con = connector.getHttpsConnection(URL);
			KeyManagerFactory keyFactory = connector.getKeyManagerFactory(
					CLIENT_KEYSTORE_PATH, storePass, keyPass);
			TrustManagerFactory trustFactory = connector
					.getTrustManagerFactory(CLIENT_TRUSTSTORE_PATH, storePass);
			connector.readSSLResponse(con, keyFactory, trustFactory);

		} catch (IOException | KeyStoreException | NoSuchAlgorithmException
				| UnrecoverableKeyException | KeyManagementException
				| CertificateException ex) {
			logger.error("Error: ", ex);
		}

	}
}
