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
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509CRL;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.Base64;

/**
 * Command for importing a CRL to a CA.
 */

public class ImportCrlCommand extends CaCommandBase {

	private static final String COMMAND_URL_PREFIX = "/ejbca/ejbca-rest-api/v1/ca/";
	private static final String COMMAND_URL_POSTFIX = "/importcrl";

	private static final Logger log = Logger.getLogger(ImportCrlCommand.class);

	private static final String ISSUER_DN_ARG = "--issuerdn";
	private static final String FILE_ARG = "--file";
	private static final String PARTITION_ARG = "--partition";

	{
		registerParameter(new Parameter(ISSUER_DN_ARG, "Issuer Dn", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "The Subject DN of the CA to import to."));
		registerParameter(new Parameter(FILE_ARG, "path", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "The path to the CRL to import."));
		registerParameter(new Parameter(PARTITION_ARG, "number", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "The CRL partition, if used. Defaults to 0."));
	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final String subjectDn = parameters.get(ISSUER_DN_ARG);
		String restUrl = new StringBuilder().append("https://").append(getHostname())
				.append(COMMAND_URL_PREFIX + URLEncoder.encode(subjectDn, StandardCharsets.UTF_8) + COMMAND_URL_POSTFIX)
				.toString();
		final String filePath = parameters.get(FILE_ARG);

		File crlFile = new File(filePath);
		if (crlFile.isDirectory()) {
			log.error("Path '" + filePath + "' points to a directory, not a file.");
			return CommandResult.CLI_FAILURE;
		}
		final X509CRL x509crl;
	//	final byte[] crlPayload;
		/*
		try {
			x509crl = (X509CRL) CertTools.getCertificateFactory().generateCRL(new FileInputStream(crlFile));
			crlPayload = x509crl.getEncoded();
			
		} catch (CRLException e) {
			log.error("File denoted by path '" + filePath + "' could not be parsed as an X509 CRL. Error message: "
					+ e.getMessage());
			return CommandResult.CLI_FAILURE;
		} catch (FileNotFoundException e) {
			log.error("CRL denoted by path '" + filePath + "' does not exist.");
			return CommandResult.CLI_FAILURE;
		}
		*/
		int partition = 0;
		if (parameters.containsKey(PARTITION_ARG)) {
			try {
				partition = Integer.valueOf(parameters.get(PARTITION_ARG));
			} catch (NumberFormatException e) {
				log.error(parameters.get(PARTITION_ARG) + " was not a number.");
				return CommandResult.CLI_FAILURE;
			}
		}
		
		
		
		try {
			byte[] crlBytes = Files.readAllBytes(crlFile.toPath());
			String crlPayload = new String(Base64.encode(crlBytes));
			
			final HttpPost request = new HttpPost(restUrl);
			MultipartEntityBuilder builder = MultipartEntityBuilder.create();
			builder.addTextBody("crlPartitionIndex", Integer.toString(partition));
			//builder.addTextBody("crlFile", new String(crlPayload), ContentType.TEXT_PLAIN);	
			builder.addBinaryBody("crlFile", crlFile);
			//builder.addTextBody("crlFile", crlPayload, ContentType.TEXT_PLAIN);
			request.setEntity(builder.build());

			try (CloseableHttpResponse response = performMultipartRequest(getSslContext(), request)) {
				final InputStream entityContent = response.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
				switch (response.getStatusLine().getStatusCode()) {
				case 404:
					log.error("Return code was: 404: " + responseString);
					break;
				case 200:
				case 201:
					log.info("Succesfully imported CRL to CA with subject DN '" + subjectDn + "'");
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
		return "importcrl";
	}

	@Override
	public String getCommandDescription() {
		return "Import a CRL for a given CA.";
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
