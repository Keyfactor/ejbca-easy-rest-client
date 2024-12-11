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
package com.keyfactor.ejbca.client.ca.management;

import java.io.File;
import java.io.FileOutputStream;
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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
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

import com.keyfactor.util.Base64;

public class CreateCrlCommand extends CaCommandBase {

	
	private static final String COMMAND_URL_PREFIX = "/ejbca/ejbca-rest-api/v1/ca/";
	private static final String COMMAND_URL_POSTFIX = "/createcrl";

	private static final Logger log = Logger.getLogger(CreateCrlCommand.class);

	private static final String ISSUER_DN_ARG = "--issuerdn";
	private static final String DELTA_ARG = "--delta";
	
	{
		registerParameter(new Parameter(ISSUER_DN_ARG, "Issuer Dn", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "The Subject DN of the sought CA."));
		registerParameter(new Parameter(DELTA_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Set this flag to create a Delta CRL"));
	}
	
	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final String subjectDn = parameters.get(ISSUER_DN_ARG);
		String restUrl = new StringBuilder().append("https://").append(getHostname())
				.append(COMMAND_URL_PREFIX + URLEncoder.encode(subjectDn, StandardCharsets.UTF_8) + COMMAND_URL_POSTFIX).toString();
		final boolean delta = parameters.containsKey(DELTA_ARG);
		restUrl += "?deltacrl=" + delta;
		
		try { 
			
				final HttpPost request = new HttpPost(restUrl);	
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
						final String issuerDn = (String) actualJsonObject.get("issuer_dn");
						getLogger().info("Issuer DN '" + issuerDn + "'");
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
	public String getFullHelpText() {
		return getCommandDescription();
	}
	
	@Override
	public String getCommandDescription() {
		return "Create a CRL for a given CA.";
	}

	@Override
	protected Logger getLogger() {
		return log;
	}
	
	@Override
	public String getMainCommand() {
		return "createcrl";
	}

}
