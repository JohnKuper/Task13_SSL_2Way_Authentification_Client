package com.johnkuper.epam.main;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TwoWayAuthenticationConnector {

	final static Logger logger = LoggerFactory.getLogger("JohnKuper");

	public HttpsURLConnection getHttpsConnection(String httpsUrl)
			throws IOException {

		URL url = new URL(httpsUrl);

		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
		con.setRequestMethod("GET");
		con.setHostnameVerifier(getHostnameVerifier());

		return con;

	}

	public KeyManagerFactory getKeyManagerFactory(String keystorePath,
			char[] storePass, char[] keyPass) throws KeyStoreException,
			NoSuchAlgorithmException, IOException, CertificateException,
			UnrecoverableKeyException {

		FileInputStream storeStream = null;
		KeyManagerFactory kmf = null;

		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			storeStream = new FileInputStream(keystorePath);
			ks.load(storeStream, storePass);

			kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, keyPass);

			storeStream.close();

		} finally {
			if (storeStream != null) {
				storeStream.close();
			}
		}

		return kmf;

	}

	public TrustManagerFactory getTrustManagerFactory(String trustStorePath,
			char[] storePass) throws KeyStoreException,
			NoSuchAlgorithmException, IOException, CertificateException {

		FileInputStream storeStream = null;
		TrustManagerFactory tmf = null;

		try {
			KeyStore ts = KeyStore.getInstance("JKS");
			storeStream = new FileInputStream(trustStorePath);
			ts.load(storeStream, storePass);
			tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);

			storeStream.close();

		} finally {
			if (storeStream != null) {
				storeStream.close();
			}
		}
		return tmf;

	}

	private HostnameVerifier getHostnameVerifier() {
		return new HostnameVerifier() {
			public boolean verify(String s, SSLSession sslSession) {
				return s.equals(sslSession.getPeerHost());
			}
		};
	}

	public void readSSLResponse(HttpsURLConnection con,
			KeyManagerFactory keyFactory, TrustManagerFactory trustFactory)
			throws NoSuchAlgorithmException, KeyManagementException {

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyFactory.getKeyManagers(),
				trustFactory.getTrustManagers(), null);
		con.setSSLSocketFactory(sslContext.getSocketFactory());

		try {
			readResponse(con);
		} catch (IOException ex) {
			logger.error("Error during readResponse: ", ex);
		}
	}

	private void readResponse(HttpsURLConnection con) throws IOException {

		InputStream inputStream = null;

		try {
			int responseCode = con.getResponseCode();

			if (responseCode == HttpURLConnection.HTTP_OK) {
				inputStream = con.getInputStream();
				logger.debug("Connection OK");
			} else {
				inputStream = con.getErrorStream();
				logger.debug("Connection error");
			}

			BufferedReader reader;
			String line = null;
			reader = new BufferedReader(new InputStreamReader(inputStream));
			while ((line = reader.readLine()) != null) {
				System.out.println(line);
			}

			inputStream.close();

		} finally {
			if (inputStream != null) {
				inputStream.close();
			}
		}
	}
}
