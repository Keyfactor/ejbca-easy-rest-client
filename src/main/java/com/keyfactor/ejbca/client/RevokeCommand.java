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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.json.simple.JSONObject;

import com.keyfactor.ejbca.util.CertTools;

/**
 * A CLI command for revoking a certificate through the EJBCA REST API.
 *
 */
public class RevokeCommand extends ErceCommandBase {

	private static final String REVOCATION_DEFAULT = "UNSPECIFIED";

	private static final String COMMAND_URL_PREFIX = "/ejbca/ejbca-rest-api/v1/certificate/";
	// Structure of URL is going to be prefix/<ISSUER DN>/<SN_IN_HEX>/suffix
	// e.g.
	// ejbca/ejbca-rest-api/v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke
	private static final String COMMAND_URL_SUFFIX = "/revoke";

	private static final String ISSUER_ARG = "--issuer";
	private static final String SN_ARG = "--serialnumber";
	private static final String CERTIFICATE_ARG = "--certificate";
	private static final String REASON_ARG = "--reason";
	private static final String DATE_ARG = "--date";

	private static final Logger log = Logger.getLogger(RevokeCommand.class);

	{
		registerParameter(new Parameter(ISSUER_ARG, "Issuer DN", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "DN of the issuing CA. Must be defined along with " + SN_ARG
						+ "OR a certificate file must be specified with " + CERTIFICATE_ARG));
		registerParameter(new Parameter(SN_ARG, "Serial number in hex", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"The serial number of the certificate in hex format. Must be defined along with " + ISSUER_ARG
						+ "OR a certificate file must be specified with " + CERTIFICATE_ARG));
		registerParameter(new Parameter(CERTIFICATE_ARG, "filename", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "The location of the PEM encoded certificate to revoke. Either this or "
						+ SN_ARG + " AND " + ISSUER_ARG + " need to be defined"));
		registerParameter(new Parameter(REASON_ARG, "Revocation reason. ", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT,
				"Revocation Reason. Must be one of the following: [NOT_REVOKED, UNSPECIFIED ,KEY_COMPROMISE, CA_COMPROMISE, AFFILIATION_CHANGED, "
						+ "SUPERSEDED, CESSATION_OF_OPERATION, CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE]. Default: UNSPECIFIED"));
		registerParameter(
				new Parameter(DATE_ARG, "date", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
						"Revocation date as a ISO 8601 Date string, eg. '2018-06-15T14:07:09Z'. Default: now"));

	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		// We need to have either a issuer+serial number or a certificate file defined.
		String issuerDn = parameters.get(ISSUER_ARG);
		String serialnumber = parameters.get(SN_ARG);
		final String certificateFile = parameters.get(CERTIFICATE_ARG);
		if (!((!StringUtils.isBlank(serialnumber) && !StringUtils.isBlank(issuerDn))
				^ !StringUtils.isBlank(certificateFile))) {
			log.error("Cannot define both (" + SN_ARG + " + " + ISSUER_ARG + ") and " + CERTIFICATE_ARG);
			return CommandResult.CLI_FAILURE;
		} else if (StringUtils.isBlank(serialnumber) && StringUtils.isBlank(issuerDn)
				&& StringUtils.isBlank(certificateFile)) {
			log.error("One combination of of " + SN_ARG + " and " + CERTIFICATE_ARG + " must be defined.");
			return CommandResult.CLI_FAILURE;
		} else if (!StringUtils.isBlank(certificateFile)) {
			// Let's read the SN from the given file.
			final List<X509Certificate> certificates;
			try {
				certificates = CertTools.getCertsFromPEM(certificateFile);
			} catch (CertificateParsingException e) {
				log.error("Certificate file " + certificateFile + " does not appear to be a correct certificate.");
				return CommandResult.CLI_FAILURE;
			} catch (FileNotFoundException e) {
				log.error("Certificate file " + certificateFile + " was not found or could not be read.");
				return CommandResult.CLI_FAILURE;
			}
			// If it's a chain, we just need to use the first cert in the chain.
			serialnumber = CertTools.getSerialNumberAsString(certificates.get(0));
			issuerDn = certificates.get(0).getIssuerDN().toString();
		}

		issuerDn = escapeInvalidUrlCharacters(issuerDn);

		String revocationDate = parameters.get(DATE_ARG);
		// Read date as now if not set
		if (StringUtils.isBlank(revocationDate)) {
			OffsetDateTime date = OffsetDateTime.now().truncatedTo(ChronoUnit.SECONDS);
			revocationDate = date.toString();
					//date.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
		}
		revocationDate = escapeInvalidUrlCharacters(revocationDate);

		String revocationReason = parameters.get(REASON_ARG);
		if (StringUtils.isBlank(revocationReason)) {
			revocationReason = REVOCATION_DEFAULT;
		}
		final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL_PREFIX)
				.append(issuerDn).append("/").append(serialnumber).append(COMMAND_URL_SUFFIX).append("?reason=")
				.append(revocationReason).append("&date=").append(revocationDate).toString();
		final String payload;
		try {
			// Construct the parameter payload
			JSONObject param = new JSONObject();
			final StringWriter out = new StringWriter();
			param.writeJSONString(out);
			payload = out.toString();
			final HttpPut request = new HttpPut(restUrl);
			request.setEntity(new StringEntity(payload));
			try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
				final InputStream entityContent = response.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
				switch (response.getStatusLine().getStatusCode()) {
				case 404:
					log.error("Return code was: 404: " + responseString);
					break;
				case 200:
				case 201:
					log.info("Certificate with serial number " + serialnumber + " from issuer " + issuerDn
							+ " was succesfully revoked.");
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
		return "revoke";
	}

	@Override
	public String getCommandDescription() {
		return "Command for revoking a certificate, either by specifying a certificate or a CA Name and certificate serial number.";
	}

	@Override
	public String getFullHelpText() {
		return getCommandDescription();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

	private String escapeInvalidUrlCharacters(final String urlElement) {
		String result = urlElement.replace(" ", "%20").replace("+", "%2b");
		return result;
	}

}
