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
package com.keyfactor.ejbca.client.enroll;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
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

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.keyfactor.ejbca.client.ErceCommandBase;
import com.keyfactor.ejbca.util.Base64;
import com.keyfactor.ejbca.util.CertTools;

public abstract class EnrollCommandBase extends ErceCommandBase {

	private static final String MAINCOMMAND = "enroll";

	protected static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll";

	
	protected  static final String DESTINATION_ARG = "--destination";
	
	private static final String SDN_ARG = "--subjectdn";
	private static final String SAN_ARG = "--subjectaltname";
	private static final String CERTIFICATE_PROFILE_ARGS = "--certificateprofile";
	private static final String END_ENTITY_PROFILE_ARGS = "--endentityprofile";
	private static final String CA_ARG = "--ca";
	private static final String USERNAME_ARGS = "--username";
	private static final String USERPASS_ARGS = "--password";
	private static final String USERPASS_PROMTP_ARGS = "-p";

	private File destination;	
	private X509Certificate certificate;
	private String username;
	private String password;
	
	{
		registerDefaultParameters();
	}

	private void registerDefaultParameters() {
		registerParameter(new Parameter(CA_ARG, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Certificate Authority name"));
		registerParameter(new Parameter(END_ENTITY_PROFILE_ARGS, "End Entity Profile Name", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "End Entity Profile Name"));
		registerParameter(new Parameter(CERTIFICATE_PROFILE_ARGS, "Certificate Profile Name", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Certificate Profile Name"));
		registerParameter(new Parameter(SDN_ARG, "Subject DN", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Requested Subject DN of the enrolled user."));
		registerParameter(new Parameter(SAN_ARG, "Subject Alt Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Requested Subject Alternative name of the enrolled user."));
		registerParameter(new Parameter(USERNAME_ARGS, "Username", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Username for the end entity"));
		registerParameter(new Parameter(USERPASS_ARGS, "Enrollment Password", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Enrollment Password for the enrolled end entity."));
		registerParameter(new Parameter(USERPASS_PROMTP_ARGS, "", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.PASSWORD,
				"Set this flag to be prompted for the Enrollment password"));
		registerParameter(new Parameter(DESTINATION_ARG, "directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Destination directory. Optional, pwd will be used if left out."));
	}

	@SuppressWarnings("unchecked")
	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final String subjectAltName = parameters.get(SAN_ARG);
		final String endEntityProfileName = parameters.get(END_ENTITY_PROFILE_ARGS);
		final String certificateProfileName = parameters.get(CERTIFICATE_PROFILE_ARGS);
		final String caName = parameters.get(CA_ARG);
		final String subjectDn = parameters.get(SDN_ARG);
		username = parameters.get(USERNAME_ARGS);
		
		if (parameters.containsKey(USERPASS_ARGS)) {
			password = parameters.get(USERPASS_ARGS);
			parameters.remove(USERPASS_ARGS);
			if (password.startsWith("file:") && (password.length() > 5)) {
				final String fileName = password.substring(5);
				// Read the password file and just take the first line as being the password
				try {
					BufferedReader br = new BufferedReader(new FileReader(fileName));
					password = br.readLine();
					br.close();
					if (password != null) {
						// Trim it, it's so easy for people to include spaces after a line, and a
						// password should never end with a space
						password = password.trim();
					}
					if ((password == null) || (password.length() == 0)) {
						getLogger().error("File '" + fileName + "' does not contain any lines.");
						return CommandResult.CLI_FAILURE;
					}
				} catch (IOException e) {
					getLogger().error("File '" + fileName + "' can not be read: " + e.getMessage());
					return CommandResult.CLI_FAILURE;
				}
			}
		} else if (parameters.containsKey(USERPASS_PROMTP_ARGS)) {
			password = parameters.get(USERPASS_PROMTP_ARGS);
			parameters.remove(USERPASS_PROMTP_ARGS);
		} else {
			getLogger().error("Password should have been specified as an argument (" + USERPASS_ARGS + ") or as a prompt flag ("+ USERPASS_PROMTP_ARGS + ")");
			return CommandResult.CLI_FAILURE;
		}
		
		if (parameters.containsKey(DESTINATION_ARG)) {
			final String destinationDirName = parameters.get(DESTINATION_ARG);
			this.destination = new File(destinationDirName);
			if (!destination.isDirectory() || !destination.canWrite()) {
				getLogger()
						.error("Directory " + destinationDirName + " was not a directory, or could not be written to.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			destination = new File(System.getProperty("user.dir"));
		}

		try {

			X500Name userDn = new X500Name(subjectDn);

			PKCS10CertificationRequest pkcs10 = getCsr(userDn, subjectAltName);

			final StringWriter pemout = new StringWriter();
			JcaPEMWriter pm = new JcaPEMWriter(pemout);
			pm.writeObject(pkcs10);
			pm.close();
			final String p10pem = pemout.toString();
			JSONObject param = new JSONObject();
			param.put("certificate_request", p10pem);
			param.put("certificate_profile_name", certificateProfileName);
			param.put("end_entity_profile_name", endEntityProfileName);
			param.put("certificate_authority_name", caName);
			param.put("username", username);
			param.put("password", password);
			param.put("include_chain", "false");
			final StringWriter out = new StringWriter();
			param.writeJSONString(out);
			final String payload = out.toString();

			final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL)
					.toString();
			final HttpPost request = new HttpPost(restUrl);
			request.setEntity(new StringEntity(payload));
			// connect to EJBCA and send the CSR and get an issued certificate back
			try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
				final InputStream entityContent = response.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);

				switch (response.getStatusLine().getStatusCode()) {
				case 404:
					getLogger().error("Return code was: 404: " + responseString);
					break;
				case 200:
				case 201:
					getLogger().info("End entity with username " + username + " has succesfully been enrolled.");
					final JSONParser jsonParser = new JSONParser();
					final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(responseString);
					final String base64cert = (String) actualJsonObject.get("certificate");
					byte[] certBytes = Base64.decode(base64cert.getBytes());
					certificate = CertTools.getCertfromByteArray(certBytes);
					byte[] pembytes = CertTools.getPemFromCertificate(certificate);
					File certificateFile = new File(destination, username + ".pem");
					// Write the resulting cert to file
					try {
						FileOutputStream fos = new FileOutputStream(certificateFile);
						fos.write(pembytes);
						fos.close();
					} catch (IOException e) {
						getLogger().error(
								"Could not write to certificate file " + certificateFile + ". " + e.getMessage());
						return CommandResult.FUNCTIONAL_FAILURE;
					}
					getLogger().info("PEM certificate written to file '" + certificateFile + "'");
					break;
				default:
					getLogger().error(
							"Return code was: " + response.getStatusLine().getStatusCode() + ": " + responseString);
					break;
				}
				return CommandResult.SUCCESS;

			} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException
					| ParseException | CertificateParsingException e) {
				getLogger().error("Could not perform request: " + e.getMessage());
				return CommandResult.FUNCTIONAL_FAILURE;
			}
		} catch (IOException e) {
			throw new IllegalStateException("Unknown IOException was caught.", e);
		}
	}

	@Override
	public String[] getCommandPath() {
		return new String[] { MAINCOMMAND };
	}

	protected abstract PKCS10CertificationRequest getCsr(final X500Name userdn, final String subjectAltName)
			throws IOException;

	protected File getDestination() {
		return destination;
	}

	protected X509Certificate getCertificate() {
		return certificate;
	}

	protected String getUsername() {
		return username;
	}
	protected String getPassword() {
		return password;
	}

}
