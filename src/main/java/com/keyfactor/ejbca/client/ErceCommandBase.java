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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
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
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.TrustAllStrategy;
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
	private static final String AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT = "-akp";
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
		registerParameter(new Parameter(AUTHENTICATION_KEYSTORE_PASS_ARGS, "Keystore Password", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Authentication Keystore Password"));
		this.registerParameter(new Parameter(AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT, "",
				MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.PASSWORD,
				"Set this flag to be prompted for the Authentication Keystore password"));

		registerParameter(new Parameter(HOSTNAME_ARG, "hostname:port", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Hostname and port, i.e localhost:8443"));
	}

	@Override
	public CommandResult execute(String... arguments) {
		boolean keystorePasswordPromt = false;
		boolean keystorePasswordSet = false;
		for (String argument : arguments) {
			if (argument.equals(AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT)) {
				keystorePasswordPromt = true;
			} else if (argument.startsWith(AUTHENTICATION_KEYSTORE_PASS_ARGS)) {
				keystorePasswordSet = true;
			}
		}
		if (keystorePasswordPromt && keystorePasswordSet) {
			// Can't do both...
			getLogger().error("Can't define both " + AUTHENTICATION_KEYSTORE_PASS_ARGS + " and specify a prompt ("
					+ AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT + ")");
			return CommandResult.CLI_FAILURE;
		}

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

		if (parameters.containsKey(AUTHENTICATION_KEYSTORE_PASS_ARGS)) {
			keystorePassword = parameters.get(AUTHENTICATION_KEYSTORE_PASS_ARGS);
			defensiveCopy.remove(AUTHENTICATION_KEYSTORE_PASS_ARGS);
			if (keystorePassword.startsWith("file:") && (keystorePassword.length() > 5)) {
				final String fileName = keystorePassword.substring(5);
				// Read the password file and just take the first line as being the password
				try {
					BufferedReader br = new BufferedReader(new FileReader(fileName));
					keystorePassword = br.readLine();
					br.close();
					if (keystorePassword != null) {
						// Trim it, it's so easy for people to include spaces after a line, and a
						// password should never end with a space
						keystorePassword = keystorePassword.trim();
					}
					if ((keystorePassword == null) || (keystorePassword.length() == 0)) {
						getLogger().error("File '" + fileName + "' does not contain any lines.");
						return null;
					}
				} catch (IOException e) {
					getLogger().error("File '" + fileName + "' can not be read: " + e.getMessage());
					return null;

				}
			}
		} else if (parameters.containsKey(AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT)) {
			keystorePassword = parameters.get(AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT);
			defensiveCopy.remove(AUTHENTICATION_KEYSTORE_PASS_ARGS_PROMPT_PROMPT);
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

	protected CloseableHttpResponse performRESTAPIRequest(final SSLContext sslContext, HttpRequestBase request)
			throws IOException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException,
			KeyStoreException {
		request.setHeader("Content-Type", "application/json");
		final HttpClientBuilder builder = HttpClientBuilder.create();
		// sslContext should be pre-created because it takes something like 25ms to
		// create, and it's the same for every call (and thread for that matter)
		final CloseableHttpClient httpClient = builder.setSSLContext(sslContext).build();
		final CloseableHttpResponse response = httpClient.execute(request);
		return response;
	}
}
