/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.ejbca.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContexts;
import org.ejbca.ui.cli.infrastructure.command.CommandBase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 *
 */
public abstract class ErceCommandBase extends CommandBase {

	private static final String AUTHENTICATION_KEYSTORE_FILE_ARGS = "--authkeystore";
	private static final String AUTHENTICATION_KEYSTORE_PASS_ARGS = "--authkeystorepass";
	private static final String HOSTNAME_ARG = "--hostname";

	private KeyStore authenticationKeystore;
	private String keystorePassword;
	private String hostname;

	{
		registerDefaultParameters();
	}

	private void registerDefaultParameters() {
		registerParameter(new Parameter(AUTHENTICATION_KEYSTORE_FILE_ARGS, "Authentication Keystore",
				MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
				"Complete path to a keystore used to authenticate"));
		registerParameter(new Parameter(AUTHENTICATION_KEYSTORE_PASS_ARGS, "Keystore Password", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Authentication Keystore Password"));
		registerParameter(new Parameter(HOSTNAME_ARG, "hostname:port", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Hostname and port, i.e localhost:8443"));
	}

	@Override
	public CommandResult execute(String... arguments) {
		ParameterContainer parameters = parameterHandler.parseParameters(arguments);
		if (parameters.containsKey(ParameterHandler.HELP_KEY)) {
			printManPage();
			return CommandResult.SUCCESS;
		} else {
			ParameterContainer strippedParameters = stripSharedParameters(parameters);
			if (strippedParameters == null) {
				// There was an error in reading the shared parameters
				return CommandResult.CLI_FAILURE;
			} else {
				return execute(strippedParameters);
			}
		}
	}

	@Override
	public String getImplementationName() {
		return "Erce: Easy REST Client for EJBCA";
	}

	/**
	 * Strips all the shared parameters and records them as local members before
	 * passing them on.
	 * 
	 */
	private ParameterContainer stripSharedParameters(ParameterContainer parameters) {
		ParameterContainer defensiveCopy = new ParameterContainer(parameters);
		final String keystoreFileName = parameters.get(AUTHENTICATION_KEYSTORE_FILE_ARGS);
		if (keystoreFileName != null) {
			defensiveCopy.remove(AUTHENTICATION_KEYSTORE_FILE_ARGS);
		}
		
		keystorePassword = parameters.get(AUTHENTICATION_KEYSTORE_PASS_ARGS);
		if (keystorePassword != null) {
			defensiveCopy.remove(AUTHENTICATION_KEYSTORE_PASS_ARGS);
		}

		try (InputStream keyStoreStream = new FileInputStream(keystoreFileName)) {
			authenticationKeystore = KeyStore.getInstance("PKCS12");
			authenticationKeystore.load(keyStoreStream, keystorePassword.toCharArray());
		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			getLogger().error(
					"Client certificate keystore can not be loaded : " + keystoreFileName + ". " + e.getMessage());
			return null;
		}
		

		hostname = parameters.get(HOSTNAME_ARG);
		if (hostname != null) {
			defensiveCopy.remove(HOSTNAME_ARG);
		}

		return defensiveCopy;
	}

	protected SSLContext getSslContext()
			throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		return SSLContexts.custom().loadKeyMaterial(authenticationKeystore, keystorePassword.toCharArray())
				.loadTrustMaterial(authenticationKeystore, new TrustAllStrategy()).build();
	}

	protected String getHostname() {
		return hostname;
	}

	protected CloseableHttpResponse performRESTAPIRequest(final SSLContext sslContext,
			HttpEntityEnclosingRequestBase request, final String payload) throws IOException, KeyManagementException,
			UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

		request.setHeader("Content-Type", "application/json");
		request.setEntity(new StringEntity(payload));
		final HttpClientBuilder builder = HttpClientBuilder.create();
		// sslContext should be pre-created because it takes something like 25ms to
		// create, and it's the same for every call (and thread for that matter)
		final CloseableHttpClient httpClient = builder.setSSLContext(sslContext).build();
		final CloseableHttpResponse response = httpClient.execute(request);
		return response;
	}
}
