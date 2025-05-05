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
package com.keyfactor.ejbca.client.configdump;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
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

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The basic ConfigDump export command, uses the getJsonConfigdump endpoint
 */

public class ConfigDumpExportCommand extends ConfigDumpCommandBase {

	private static final Logger log = Logger.getLogger(ConfigDumpExportCommand.class);

	
	private static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v1/configdump";
	
	private static final String LOCATION_ARG = "--out";
	private static final String IGNORE_ERRORS_ARG = "--ignoreerrors";
	private static final String DEFAULTS_ARG = "--defaults"; 
	private static final String EXTERNAL_CAS_ARG =  "--externalcas"; 
	private static final String EXPORT_CAS_FOR_PEER_IMPORT_ARG =  "--exportCasForPeerImport";
	private static final String INCLUDE_ARG = "--include"; 
	private static final String EXCLUDE_ARG = "--exclude"; 
	
	{
		registerParameter(new Parameter(LOCATION_ARG, "Directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Directory in which to place YAML exports. Present working directory will be used if not set."));
		registerParameter(new Parameter(IGNORE_ERRORS_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Print a warning instead of aborting and throwing an exception on errors. Default is false."));
		registerParameter(new Parameter(DEFAULTS_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Also include fields having the default value. Default is false."));
		registerParameter(new Parameter(EXTERNAL_CAS_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Enables export of external CAs (i.e. CAs where there's only a certificate and nothing else). Default is false."));
		registerParameter(new Parameter(EXPORT_CAS_FOR_PEER_IMPORT_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG,"Export an CA to be imported in a Peer as configdump. Default is false."));
		registerParameter(new Parameter(INCLUDE_ARG, "Semicolon separated list", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Names of items/types to include in the export. The syntax is identical to that of exclude. For items of types that aren't listed, everything is included."));
		registerParameter(new Parameter(EXCLUDE_ARG, "Semicolon separated list", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Names of items/types to exclude in the export, separated by semicolon. Type and name is separated by a colon, and wildcards \"*\" are allowed. " 
						+ "Both are case-insensitive. E.g. exclude=\"*:Example CA;cryptotoken:Example*;systemconfiguration:*\". Supported types are: ACMECONFIG/acme-config, "
						+ "AUTOENROLLMENTCONFIG/autoenrollment-config, CA/certification-authorities, CRYPTOTOKEN/crypto-tokens, PUBLISHER/publishers, APPROVALPROFILE/approval-profiles, "
						+ "CERTPROFILE/certificate-profiles, EEPROFILE/end-entity-profiles, SERVICE/services, ROLE/admin-roles, KEYBINDING/internal-key-bindings, ADMINPREFS/admin-preferences, "
						+ "OCSPCONFIG/ocsp-configuration, PEERCONNECTOR/peer-connectors, SCEPCONFIG/scep-config, CMPCONFIG/cmp-config, ESTCONFIG/est-config, VALIDATOR/validators, CTLOG/ct-logs, "
						+ "EXTENDEDKEYUSAGE/extended-key-usage, CERTEXTENSION/custom-certificate-extensions, OAUTHKEY/trusted-oauth-providers, AVAILABLEPROTOCOLS/available-protocols"));
	}
	
	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final File destination;	
		if (parameters.containsKey(LOCATION_ARG)) {
			final String destinationDirName = parameters.get(LOCATION_ARG);
			destination = new File(destinationDirName);
			if (!destination.isDirectory() || !destination.canWrite()) {
				getLogger()
						.error("Directory " + destinationDirName + " was not a directory, or could not be written to.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			destination = new File(System.getProperty("user.dir"));
		}
		StringBuilder stringBuilder = new StringBuilder().append("https://").append(getHostname())
				.append(COMMAND_URL);
		
		if(parameters.containsKey(IGNORE_ERRORS_ARG)) {
			stringBuilder = stringBuilder.append("?ignoreerrors=true");
		} else {
			stringBuilder = stringBuilder.append("?ignoreerrors=false");
		}
		if(parameters.containsKey(DEFAULTS_ARG)) {
			stringBuilder = stringBuilder.append("&defaults=true");
		} else {
			stringBuilder = stringBuilder.append("&defaults=false");
		}
		if(parameters.containsKey(EXTERNAL_CAS_ARG)) {
			stringBuilder = stringBuilder.append("&externalcas=true");
		} else {
			stringBuilder = stringBuilder.append("&externalcas=false");
		}		
		if(parameters.containsKey(EXPORT_CAS_FOR_PEER_IMPORT_ARG)) {
			stringBuilder = stringBuilder.append("&exportCasForPeerImport=true");
		} else {
			stringBuilder = stringBuilder.append("&exportCasForPeerImport=false");
		}		
		if(parameters.containsKey(INCLUDE_ARG)) {
			stringBuilder.append("&include=").append(parameters.get(INCLUDE_ARG));
		}
		if(parameters.containsKey(EXCLUDE_ARG)) {
			stringBuilder.append("&exclude=").append(parameters.get(EXCLUDE_ARG));
		}
		
		final String restUrl = stringBuilder.toString();
		
		
		try {	
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
					final JSONObject returnObject = (JSONObject) jsonParser.parse(responseString);		
					System.err.println(returnObject.toJSONString());
					for(Object key : returnObject.keySet()) {
						writeDumpDirectory((JSONObject) returnObject.get((String) key), destination, (String) key);
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
		return "export";
	}

	@Override
	public String getCommandDescription() {
		return "Provides a basic full ConfigDump export of EJBCA. Note that ConfigDump is an enterprise feature.";
	}

	@Override
	public String getFullHelpText() {
		return getCommandDescription();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}
	
	private void writeDumpDirectory(final JSONObject jsonObject, final File baseDirectory, final String directoryName) throws IOException {	
		if(!jsonObject.isEmpty()) {
			File dumpDirectory = new File(baseDirectory, directoryName);
			if(!dumpDirectory.exists() && !dumpDirectory.mkdir()) {
				String msg = "Could not create directory " + directoryName + ", cannot continue with dump.";
				getLogger().error(msg);
				throw new IOException();
			} else {
				for (Object key : jsonObject.keySet()) {
					File export = new File(dumpDirectory, key + ".yaml");
					JSONObject dumpFile = (JSONObject) jsonObject.get(key);
					ObjectMapper mapper = new ObjectMapper();
					try (PrintWriter out = new PrintWriter(export)) {
					    out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(dumpFile));
					}
				}
			}
		}	
	}

}
