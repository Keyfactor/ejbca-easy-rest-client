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

/**
 * Allows for the download of the latest CRL from a CA
 */

public class GetLatestCrlCommand extends CaCommandBase {

	private static final String COMMAND_URL_PREFIX = "/ejbca/ejbca-rest-api/v1/ca/";
	private static final String COMMAND_URL_POSTFIX = "/getLatestCrl";

	private static final Logger log = Logger.getLogger(GetLatestCrlCommand.class);

	private static final String ISSUER_DN_ARG = "--issuerdn";
	private static final String DESTINATION_ARG = "--destination";
	private static final String DELTA_ARG = "--delta";
	private static final String INDEX_ARG = "--index";

	{
		registerParameter(new Parameter(ISSUER_DN_ARG, "Issuer Dn", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "The Subject DN of the sought CA."));
		registerParameter(new Parameter(DESTINATION_ARG, "directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Destination directory. Optional, present working directory will be used if left out."));
		registerParameter(new Parameter(DELTA_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Set this flag to retrieve the latest Delta CRL"));
		registerParameter(new Parameter(INDEX_ARG, "number", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "A CRL index for a partitioned CRL, if applicable"));
	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final String subjectDn = parameters.get(ISSUER_DN_ARG);
		String restUrl = new StringBuilder().append("https://").append(getHostname())
				.append(COMMAND_URL_PREFIX + URLEncoder.encode(subjectDn, StandardCharsets.UTF_8) + COMMAND_URL_POSTFIX).toString();
		
		final File destination;	
		if (parameters.containsKey(DESTINATION_ARG)) {
			final String destinationDirName = parameters.get(DESTINATION_ARG);
			destination = new File(destinationDirName);
			if (!destination.isDirectory() || !destination.canWrite()) {
				getLogger()
						.error("Directory " + destinationDirName + " was not a directory, or could not be written to.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			destination = new File(System.getProperty("user.dir"));
		}
		
		final boolean delta = parameters.containsKey(DELTA_ARG);
		
		final Integer partitionIndex;
		if (parameters.containsKey(INDEX_ARG)) {
			partitionIndex = Integer.valueOf(parameters.get(INDEX_ARG));
		} else {
			partitionIndex = null;
		}
		
		try {
			restUrl += "?deltaCrl=" + delta;
			if(partitionIndex != null) {
				restUrl += "crlPartitionIndex=" + partitionIndex.intValue();
			}		
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
					final String format = (String) actualJsonObject.get("response_format");
					final String crlString = (String) actualJsonObject.get("crl");
					if(format.equals("DER")) {
						File crlFile = new File(destination, subjectDn + ".crl");
						// Write the resulting cert to file
						try {
							FileOutputStream fos = new FileOutputStream(crlFile);
							fos.write(Base64.decode(crlString.getBytes()));
							fos.close();
						} catch (IOException e) {
							getLogger().error(
									"Could not write to CRL file " + crlFile + ". " + e.getMessage());
							return CommandResult.FUNCTIONAL_FAILURE;
						}
						getLogger().info("CRL written to file '" + crlFile + "'");
					} else {
						log.error("Unknown response format: " + format);
						return CommandResult.FUNCTIONAL_FAILURE;
					}
					
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
		return "downloadcrl";
	}

	@Override
	public String getCommandDescription() {
		return "Download the latest CRL of a given CA.";
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
