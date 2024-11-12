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

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Lists all available CAs
 */

public class ListCaCommand extends CaCommandBase {

	private static final String COMMAND_URL= "/ejbca/ejbca-rest-api/v1/ca";

	private static final Logger log = Logger.getLogger(ListCaCommand.class);
	
	private static final String ISSUER_DN_LABEL = "issuer_dn";
	private static final String IS_EXTERNAL_LABEL = "external";
	private static final String SUBJECT_DN_LABEL = "subject_dn";
	private static final String NAME_LABEL = "name";
	private static final String ID_LABEL = "id";
	private static final String EXPIRES_LABEL = "expiration_date";
	
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
					final JSONObject returnObject = (JSONObject) jsonParser.parse(responseString);
					final JSONArray jsonArray = (JSONArray) returnObject.get("certificate_authorities");
					@SuppressWarnings("unchecked")
		            Iterator<JSONObject> iterator = jsonArray.iterator();
					StringBuilder stringBuilder = new StringBuilder();
					List<String[]> caContents = new ArrayList<>();
		            while (iterator.hasNext()) {
		            	JSONObject caRow = iterator.next();
		            	final String issuerDn = (String) caRow.get(ISSUER_DN_LABEL);
		            	final String subjectDn = (String) caRow.get(SUBJECT_DN_LABEL);
		            	final Long caId = (Long) caRow.get(ID_LABEL);
		            	final String name = (String) caRow.get(NAME_LABEL);
		            	final String expires = (String) caRow.get(EXPIRES_LABEL);
		            	final Boolean isExternal = (Boolean) caRow.get(IS_EXTERNAL_LABEL);
		            	caContents.add(new String[]{name, caId.toString(), isExternal.toString(), subjectDn, issuerDn, expires});

		            }
		            stringBuilder.append(bold("The following CAs are available in the current instance:\n"));
		            stringBuilder.append(formatTable(1, new String[] { "Name:", "CA ID:", "External", "Subject DN:", "Issuer DN:", "Expires:" }, caContents));
		            stringBuilder.append("\n");
					log.info(stringBuilder.toString());
					
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
		return "listcas";
	}
	
	@Override
	public String getCommandDescription() {
		return "Lists all available CAs";
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
