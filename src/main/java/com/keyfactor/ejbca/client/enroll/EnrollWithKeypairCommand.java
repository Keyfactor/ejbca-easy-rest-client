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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.keys.KeyTools;

/**
 * A CLI command which invokes the "pkcs10enroll" REST command 
 *
 */
public class EnrollWithKeypairCommand extends EnrollCommandBase {

	private static final String PUBKEY_ARGS = "--pubkey";
	private static final String PRIVKEY_ARGS = "--privkey";
	
	private String pubkeyFilename;
	private String privkeyFilename;

	{
		registerParameter(new Parameter(PUBKEY_ARGS, "Public Key File", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Complete path to the public key to sign"));
		registerParameter(
				new Parameter(PRIVKEY_ARGS, "Private Key file", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
						ParameterMode.ARGUMENT, "Complete path to the private key associated with the public key."));
	}

	private static final Logger log = Logger.getLogger(EnrollWithKeypairCommand.class);

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		pubkeyFilename = parameters.get(PUBKEY_ARGS);
		privkeyFilename = parameters.get(PRIVKEY_ARGS);		
		return super.execute(parameters);
	}

	private PublicKey readPublicKey(final String filename) throws IOException {
		FileReader keyReader = new FileReader(new File(filename));
		try (PemReader pemReader = new PemReader(keyReader)) {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			return KeyTools.getPublicKeyFromBytes(content);
		}
	}

	private PrivateKey readPrivateKey(final String filename) throws IOException {
		try (FileReader keyReader = new FileReader(new File(filename))) {

			PEMParser pemParser = new PEMParser(keyReader);
			Object pemObject = pemParser.readObject();
			PrivateKeyInfo privateKeyInfo;
			if (pemObject instanceof PEMKeyPair) {
				privateKeyInfo = ((PEMKeyPair) pemObject).getPrivateKeyInfo();
			} else {
				privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
			}
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			return converter.getPrivateKey(privateKeyInfo);
		}
	}

	@Override
	public String getMainCommand() {
		return "withkeys";
	}

	@Override
	public String getCommandDescription() {
		return "Command for enrolling to EJBCA with a locally created key pair";
	}

	@Override
	public String getFullHelpText() {
		return "Command for enrolling to EJBCA. Can be used to enroll using a supplied public and private key. Example usage: --authkeystore=/Users/foo/superadmin.p12"
				+ " --authkeystorepass=foo123 --pubkey=/Users/foo/public.pem --privkey=/Users/foo/key.pem --endentityprofile=simple --certificateprofile=simple --ca=foo "
				+ " --subjectaltname=\"dnsName=foo.com\"  --hostname=localhost:8443 --destination=/Users/foo/ --subjectdn=\"CN=foo\" --username=foo --password=foo123";
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

	@Override
	protected PKCS10CertificationRequest getCsr(final X500Name userdn, final String subjectAltName) throws IOException {
		final PublicKey publicKey = readPublicKey(pubkeyFilename);
		final PrivateKey privateKey = readPrivateKey(privkeyFilename);
		return generateCertificateRequest(userdn, subjectAltName, publicKey, privateKey);
	}

}
