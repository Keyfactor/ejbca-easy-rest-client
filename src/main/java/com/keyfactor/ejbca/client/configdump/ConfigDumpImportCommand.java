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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Basic implementation of the configdump import endpoint
 */

public class ConfigDumpImportCommand extends ConfigDumpCommandBase {

	private static final Logger log = Logger.getLogger(ConfigDumpImportCommand.class);

	private static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v1/configdump";

	private static final String LOCATION_ARG = "--in";
	private static final String IGNORE_ERRORS_ARG = "--ignoreerrors";
	private static final String INITIALIZE_ARG = "--initialize";
	private static final String CONTINUE_ARG = "--continue";
	private static final String OVERWRITE_ARG = "--overwrite";
	private static final String RESOLVE_ARG = "--resolve";
	private static final String EXPAND_ARG = "--expand";
	
	private static final String YAML_POSTFIX = ".yaml";

	private static final Set<String> OVERWRITE_OPTIONS = new HashSet<>(Arrays.asList("abort", "skip", "yes"));
	private static final Set<String> RESOLVE_OPTIONS = new HashSet<>(Arrays.asList("abort", "skip", "usedefault"));

	{
		registerParameter(new Parameter(LOCATION_ARG, "Directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Directory in which to find YAML imports. Present working directory will be used if not set."));
		registerParameter(new Parameter(IGNORE_ERRORS_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Add to warnings instead of aborting on errors. Default is false."));
		registerParameter(new Parameter(INITIALIZE_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Generate initial certificate for CAs on import. Default is false."));
		registerParameter(new Parameter(CONTINUE_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Continue on errors. Default is to abort."));
		registerParameter(new Parameter(OVERWRITE_ARG, "<value>", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"How to handle already existing configuration. Options are 'abort', 'skip' or 'yes'. Default value is abort."));
		registerParameter(new Parameter(RESOLVE_ARG, "<value>", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"How to resolve missing references. Options are 'abort', 'skip' or 'useDefault'. Default value is abort."));
		registerParameter(new Parameter(EXPAND_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG,
				"Expand variables by replacing references in form ${VARIABLE_NAME} with values of matching environment variables, e.g. VARIABLE_NAME. Default is false."));
	}

	@Override
	public String getMainCommand() {
		return "import";
	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final File source;
		if (parameters.containsKey(LOCATION_ARG)) {
			final String sourceDirName = parameters.get(LOCATION_ARG);
			source = new File(sourceDirName);
			if (!source.isDirectory() || !source.canRead()) {
				getLogger().error("Directory " + sourceDirName + " was not a directory, or could not be read from.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			source = new File(System.getProperty("user.dir"));
		}
		StringBuilder stringBuilder = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL);
		if (parameters.containsKey(IGNORE_ERRORS_ARG)) {
			stringBuilder = stringBuilder.append("?ignoreerrors=true");
		} else {
			stringBuilder = stringBuilder.append("?ignoreerrors=false");
		}
		if (parameters.containsKey(INITIALIZE_ARG)) {
			stringBuilder = stringBuilder.append("&initialize=true");
		} else {
			stringBuilder = stringBuilder.append("&initialize=false");
		}
		if (parameters.containsKey(CONTINUE_ARG)) {
			stringBuilder = stringBuilder.append("&continue=true");
		} else {
			stringBuilder = stringBuilder.append("&continue=false");
		}
		if (parameters.containsKey(OVERWRITE_ARG)) {
			final String argument = parameters.get(OVERWRITE_ARG);
			if (OVERWRITE_OPTIONS.contains(argument.toLowerCase())) {
				stringBuilder = stringBuilder.append("&overwrite=" + argument);
			} else {
				getLogger().error("'" + argument + "' is not a valid option for overwrite.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			stringBuilder = stringBuilder.append("&overwrite=abort");
		}
		if (parameters.containsKey(RESOLVE_ARG)) {
			final String argument = parameters.get(RESOLVE_ARG);
			if (RESOLVE_OPTIONS.contains(argument.toLowerCase())) {
				stringBuilder = stringBuilder.append("&resolve=" + argument);
			} else {
				getLogger().error("'" + argument + "' is not a valid option for resolve.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			stringBuilder = stringBuilder.append("&resolve=abort");
		}
		if (parameters.containsKey(EXPAND_ARG)) {
			stringBuilder = stringBuilder.append("&expand=true");
		} else {
			stringBuilder = stringBuilder.append("&expand=false");
		}

		final String restUrl = stringBuilder.toString();

		StringBuilder payloadBuilder = new StringBuilder();
		//newlines are added in for debuggning purposes.
		payloadBuilder.append("{\n");
		File[] directories = source.listFiles((dir, name) -> new File(dir, name).isDirectory());
		for(int i = 0; i < directories.length; i++) {
			File directory = directories[i];
			payloadBuilder.append("\"").append(directory.getName()).append("\": {\n");
			File[] dumpFiles = directory.listFiles((dir, name) -> new File(dir, name).isFile() && name.endsWith(YAML_POSTFIX));
			for(int j = 0; j < dumpFiles.length; j++) {
				File dumpFile = dumpFiles[j];
				payloadBuilder.append("\"").append(dumpFile.getName().substring(0, dumpFile.getName().indexOf(YAML_POSTFIX))).append("\": ");
				try {
					payloadBuilder.append(new String(Files.readAllBytes(dumpFile.toPath())));
				} catch (IOException e) {
					log.error("Could not read file " + dumpFile.getAbsolutePath() + ", exception says: "
							+ e.getMessage());
					return CommandResult.CLI_FAILURE;
				}
				if(j < (dumpFiles.length - 1)) {
					//Replace newline scanned in from file
					payloadBuilder.setLength(payloadBuilder.length()-1);
					payloadBuilder.append(",\n");
				} 
			}
			if(i < (directories.length - 1)) {
				payloadBuilder.append("},\n");
			} else {
				payloadBuilder.append("}\n");
			}
		}
		payloadBuilder.append("} ");
		String payload = payloadBuilder.toString();				
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
		JsonNode jsonNode;
		try {
			jsonNode = objectMapper.readTree( payload);
			payload = objectMapper.writeValueAsString(jsonNode);
		} catch (JsonProcessingException e) {
			throw new IllegalStateException(e);
		}        
		

		try {
			final HttpPost request = new HttpPost(restUrl);
			request.setEntity(new StringEntity(payload));
			try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
				final InputStream entityContent = response.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);

				switch (response.getStatusLine().getStatusCode()) {
				case 404:
					getLogger().error("Return code was: 404: " + responseString);
					break;
				case 200:
				case 201:
					getLogger().info("ConfigDump import was sucessful: " + responseString);
					break;
				default:
					getLogger().error(
							"Return code was: " + response.getStatusLine().getStatusCode() + ": " + responseString);
					break;
				}
				return CommandResult.SUCCESS;

			} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException
					| KeyStoreException e) {
				getLogger().error("Could not perform request: " + e.getMessage());
				return CommandResult.FUNCTIONAL_FAILURE;
			}
		} catch (IOException e) {
			throw new IllegalStateException("Unknown IOException was caught.", e);
		}
	}

	@Override
	public String getCommandDescription() {
		return "Provides a basic full ConfigDump import of EJBCA. Note that ConfigDump is an enterprise feature.";
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
