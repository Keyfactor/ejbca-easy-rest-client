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
package com.keyfactor.ejbca.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
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
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A CLI command for retrieving the status o the EJBCA REST API.
 *
 */
public class GetStatusCommand extends ErceCommandBase {


	private static final String COMMAND_URL= "/ejbca/ejbca-rest-api/v2/certificate/status";

	private static final Logger log = Logger.getLogger(GetStatusCommand.class);


	@Override
	protected CommandResult execute(ParameterContainer parameters) {

		
		final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL).toString();
		try {
			// Construct the parameter payload
			JSONObject param = new JSONObject();
			final StringWriter out = new StringWriter();
			param.writeJSONString(out);
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
					final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(responseString);
					final String status = (String) actualJsonObject.get("status");
					final String version = (String) actualJsonObject.get("version");
					final String revision = (String) actualJsonObject.get("revision");
					log.info("Current Status of this instance of EJBCA is: " + status);
					log.info("Current REST API Version: " + version);
					log.info("Current version of EJBCA is: " + revision);					
					break;
				default:
					log.error("Return code was: " + response.getStatusLine().getStatusCode() + ": " + responseString);
					break;
				}
			} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException
					| KeyStoreException | ParseException e) {
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
		return "status";
	}

	@Override
	public String getCommandDescription() {
		return "Command for getting the status of a resource";
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
