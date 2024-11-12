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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

/**
 * A CLI command which invokes the "pkcs10enroll" REST command
 *
 */
public class EnrollGenKeysCommand extends EnrollCommandBase {

	private static final String KEYALG_ARG = "--keyalg";
	private static final String KEYSPEC_ARG = "--keyspec";

	private static final Set<String> RSA_KEY_SIZES = new LinkedHashSet<>(
			Arrays.asList("1024", "1536", "2048", "3072", "4096", "6144", "8192"));
	private static final Set<String> EC_CURVES = AlgorithmTools.getNamedEcCurvesMap().keySet();

	private PublicKey publicKey;
	private PrivateKey privateKey;

	{
		registerParameter(new Parameter(KEYALG_ARG, "cipher", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Cipher must be one of [ " + AlgorithmConstants.KEYALGORITHM_RSA + ", " + AlgorithmConstants.KEYALGORITHM_EC + ", "
						+ AlgorithmConstants.KEYALGORITHM_ED25519 + ", " + AlgorithmConstants.KEYALGORITHM_ED448 + "]"));
		StringBuilder ecCurvesFormatted = new StringBuilder();
		ecCurvesFormatted.append("[");
		for (String curveName : EC_CURVES) {
			ecCurvesFormatted.append(" ").append(curveName).append(",");
		}
		ecCurvesFormatted.deleteCharAt(ecCurvesFormatted.lastIndexOf(","));
		ecCurvesFormatted.append(" ]");
		registerParameter(new Parameter(KEYSPEC_ARG, "Key Specification", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Key Specification.\n If cipher was RSA, must be one of [ 1024, 1536, 2048, 3072, 4096, 6144, 8192 ].\n If cipher was EC, must be one of "
						+ ecCurvesFormatted + ". Should be omitted for Ed25519 and Ed448."));
	}

	private static final Logger log = Logger.getLogger(EnrollGenKeysCommand.class);

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		Security.addProvider(new BouncyCastleProvider());
		final String keySpec = parameters.get(KEYSPEC_ARG);
		String keyAlg = parameters.get(KEYALG_ARG);

		switch (keyAlg.toUpperCase()) {
		case "RSA":
			keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
			if (!RSA_KEY_SIZES.contains(keySpec)) {
				log.error("Key size " + keySpec + " is invalid for RSA Keys.");
				return CommandResult.CLI_FAILURE;
			}
			break;
		case "EC":
		case "ECDSA":
			keyAlg = AlgorithmConstants.KEYALGORITHM_EC;
			if (!EC_CURVES.contains(keySpec)) {
				log.error(keySpec + " is not a known EC curve.");
				return CommandResult.CLI_FAILURE;
			}
			break;
		case "ED25519":
			keyAlg = AlgorithmConstants.KEYALGORITHM_ED25519;
			break;
		case "ED448":
			keyAlg = AlgorithmConstants.KEYALGORITHM_ED448;
			break;
		default:
			log.error("Key Algorithm " + keyAlg + " was unknown.");
			return CommandResult.CLI_FAILURE;
		}
		KeyPair keyPair;
		try {
			keyPair = KeyTools.genKeys(keySpec, keyAlg);
		} catch (InvalidAlgorithmParameterException e) {
			log.error("Caught invalid parameter exception: " + e.getMessage());
			return CommandResult.CLI_FAILURE;
		}
		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
		CommandResult result = super.execute(parameters);
		// Build a PKCS#12 that we can write to disk
		byte[] encodedKeystore;
		try {
			KeyStore pkcs12 = createP12(getUsername(), this.privateKey, getCertificate(), getPassword());
			this.privateKey = null;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			pkcs12.store(baos, getPassword().toCharArray());
			encodedKeystore = baos.toByteArray();
		} catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException
				| IOException e) {
			log.error("Could not generate PKCS#12 keystore.", e);
			return CommandResult.FUNCTIONAL_FAILURE;
		}

		try {
			File p12File = new File(getDestination(), getUsername() + ".p12");
			FileOutputStream fos = new FileOutputStream(p12File);
			fos.write(encodedKeystore);
			fos.close();
			log.info("PKCS#12 written to '" + p12File.getAbsolutePath() + "'");
		} catch (FileNotFoundException e) {
			log.error("Destination directory not found: " + e.getMessage());
			return CommandResult.FUNCTIONAL_FAILURE;
		} catch (IOException e) {
			throw new IllegalStateException("Could not write to file for unknown reason", e);
		}

		return result;
	}

	private static KeyStore createP12(final String alias, final PrivateKey privateKey,
			final X509Certificate certificate, final String keystorePassword)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyStore store;
		try {
			store = KeyStore.getInstance("PKCS12-3DES-3DES", BouncyCastleProvider.PROVIDER_NAME);
			store.load(null, keystorePassword.toCharArray());
		} catch (KeyStoreException | NoSuchProviderException | IOException e) {
			throw new IllegalStateException("Could not create keystore.", e);
		}

		// Certificate chain
		if (certificate == null) {
			throw new IllegalArgumentException("Parameter certificate cannot be null.");
		}
		final Certificate[] chain = new Certificate[1];

		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CertificateParsingException("Could not create certificate factory", e);
		}
		chain[0] = certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
		// Set attributes on user-certificate
		try {
			final PKCS12BagAttributeCarrier certBagAttr = (PKCS12BagAttributeCarrier) chain[0];
			certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
			// in this case we just set the local key id to that of the public key
			certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					createSubjectKeyId(chain[0].getPublicKey()));
		} catch (ClassCastException e) {
			log.error("ClassCastException setting BagAttributes, can not set friendly name: ", e);
		}
		try {
			// "Clean" private key, i.e. remove any old attributes,
			// As well as convert any EdDSA key to v1 format that is understood by openssl
			// v1.1.1 and earlier
			// EdDSA (Ed25519 or Ed448) keys have a v1 format, with only the private key,
			// and a v2 format that includes both the private and public
			final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			final PrivateKeyInfo v1PkInfo = new PrivateKeyInfo(pkInfo.getPrivateKeyAlgorithm(),
					pkInfo.parsePrivateKey());
			final KeyFactory keyfact = KeyFactory.getInstance(privateKey.getAlgorithm(),
					BouncyCastleProvider.PROVIDER_NAME);
			final PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(v1PkInfo.getEncoded()));
			// The PKCS#12 bag attributes PKCSObjectIdentifiers.pkcs_9_at_friendlyName and
			// PKCSObjectIdentifiers.pkcs_9_at_localKeyId
			// are set automatically by BC when setting the key entry
			store.setKeyEntry(alias, pk, null, chain);

			return store;
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("BouncyCastle provider was not found.", e);
		} catch (KeyStoreException e) {
			throw new IllegalStateException("PKCS12 keystore type could not be instanced.", e);
		} catch (IOException e) {
			throw new IllegalStateException("IOException should not be thrown when instancing an empty keystore.", e);
		}
	}

	/**
	 * create the subject key identifier.
	 * 
	 * @param pubKey the public key
	 * 
	 * @return SubjectKeyIdentifer asn.1 structure
	 */
	private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey pubKey) {
		try {
			final ASN1Sequence keyASN1Sequence;
			try (final ASN1InputStream pubKeyAsn1InputStream = new ASN1InputStream(
					new ByteArrayInputStream(pubKey.getEncoded()));) {
				final Object keyObject = pubKeyAsn1InputStream.readObject();
				if (keyObject instanceof ASN1Sequence) {
					keyASN1Sequence = (ASN1Sequence) keyObject;
				} else {
					// PublicKey key that doesn't encode to a ASN1Sequence. Fix this by creating a
					// BC object instead.
					final PublicKey altKey = (PublicKey) KeyFactory
							.getInstance(pubKey.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME)
							.translateKey(pubKey);
					try (final ASN1InputStream altKeyAsn1InputStream = new ASN1InputStream(
							new ByteArrayInputStream(altKey.getEncoded()))) {
						keyASN1Sequence = (ASN1Sequence) altKeyAsn1InputStream.readObject();
					}
				}
				X509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();
				return x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyASN1Sequence));
			}
		} catch (Exception e) {
			final RuntimeException e2 = new RuntimeException("error creating key"); // NOPMD
			e2.initCause(e);
			throw e2;
		}
	}

	@Override
	public String getMainCommand() {
		return "genkeys";
	}

	@Override
	public String getCommandDescription() {
		return "Command for enrolling to EJBCA, creating a keypair into the directory specified by the "
				+ DESTINATION_ARG + " flag (or the PWD if none specified)";
	}

	@Override
	public String getFullHelpText() {
		return getCommandDescription();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

	@Override
	protected PKCS10CertificationRequest getCsr(final X500Name userdn, final String subjectAltName) throws IOException {
		return generateCertificateRequest(userdn, subjectAltName, publicKey, privateKey);
	}

}
