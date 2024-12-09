package com.keyfactor.ejbca.client.ca.management;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

public class DeactivateCaCommand extends CaCommandBase {

	private static final String COMMAND_URL_PREFIX = "/ejbca/ejbca-rest-api/v1/ca_management/";
	private static final String COMMAND_URL_POSTFIX = "/activate";

	private static final Logger log = Logger.getLogger(DeactivateCaCommand.class);

	private static final String CA_NAME = "--name";

	{
		registerParameter(new Parameter(CA_NAME, "Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Name of the CA to activate."));
	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		// Make sure DN is normalized
		final String caName = parameters.get(CA_NAME);
		String restUrl = new StringBuilder().append("https://").append(getHostname())
				.append(COMMAND_URL_PREFIX + URLEncoder.encode(caName, StandardCharsets.UTF_8) + COMMAND_URL_POSTFIX)
				.toString();
		final HttpPut request = new HttpPut(restUrl);
		try {
			try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
				final InputStream entityContent = response.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
				switch (response.getStatusLine().getStatusCode()) {
				case 404:
					log.error("Return code was: 404: " + responseString);
					break;
				case 200:
				case 201:
					log.info("CA with name '" + caName + "' was activated.");
					break;
				default:
					log.error("Return code was: " + response.getStatusLine().getStatusCode() + ": " + responseString);
					break;
				}
			} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException
					| KeyStoreException e) {
				log.error("Could not perform request: " + e.getMessage());
				return CommandResult.FUNCTIONAL_FAILURE;
			}
		} catch (IOException e) {
			throw new IllegalStateException("Unknown IOException was caught.", e);
		}
		return CommandResult.SUCCESS;
	}

	@Override
	public String getMainCommand() {
		return "activate";
	}

	@Override
	public String getCommandDescription() {
		return "Activate a CA";
	}

	@Override
	public String getFullHelpText() {
		return getCommandDescription();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

}
