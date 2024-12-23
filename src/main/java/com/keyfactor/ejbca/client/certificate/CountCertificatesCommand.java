/*************************************************************************
 *                                                                       *
 *  Keyfactor Community                                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.ejbca.client.certificate;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.keyfactor.ejbca.client.ca.management.ActivateCaCommand;

/**
 * Connects to the /v2/certificate/count endpoint
 */

public class CountCertificatesCommand extends CertificateCommandBase {

	private static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v2/certificate/count";

	private static final Logger log = Logger.getLogger(ActivateCaCommand.class);
	
	private static final String ACTIVE_ARG = "--onlyActive";

	{
		registerParameter(new Parameter(ACTIVE_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Set this flag to restrict the count to only active certificates."));
	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		boolean onlyActive = parameters.containsKey(ACTIVE_ARG);
		final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL).append((onlyActive ? "?isActive=true" : "?isActive=false"))
				.toString();		
		final HttpGet request = new HttpGet(restUrl);
		try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
			final InputStream entityContent = response.getEntity().getContent();
			String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
			switch (response.getStatusLine().getStatusCode()) {
			case 404:
				log.error("Return code was: 404: " + responseString);
				break;
			case 200:
			case 201:
				final JSONParser jsonParser = new JSONParser();			
				final JSONObject jsonObject = (JSONObject) jsonParser.parse(responseString);
				final Long count = (Long) jsonObject.get("count");
				log.info("Current database contains " + count + (onlyActive ? " active" : "") + " certificates.");
				break;
			default:
				log.error("Return code was: " + response.getStatusLine().getStatusCode() + ": " + responseString);
				break;
			}
		} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException
				| KeyStoreException | ParseException e) {
			log.error("Could not perform request: " + e.getMessage());
			return CommandResult.FUNCTIONAL_FAILURE;
		} catch (IOException e) {
			throw new IllegalStateException("Unknown IOException was caught.", e);
		}
		
		return CommandResult.SUCCESS;
	}

	@Override
	public String getCommandDescription() {
		return "Returns a count of all certificates in the database.";
	}

	@Override
	public String getFullHelpText() {
		StringBuilder stringBuilder = new StringBuilder(getCommandDescription() + "\n\n");
		stringBuilder.append("Can be restricted to showing only active certificates with the --onlyActive flag");
		return stringBuilder.toString();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}
	
	@Override
	public String getMainCommand() {
		return "count";
	}

}
