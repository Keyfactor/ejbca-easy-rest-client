/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.ejbca.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;

import com.keyfactor.ejbca.x500.CeSecoreNameStyle;

/**
 *
 */
public class CertTools {

	private static final Logger log = LogManager.getLogger(CertTools.class);

	/** Kerberos altName for smart card logon */
	private static final String KRB5PRINCIPAL = "krb5principal";

	private static final String EMAIL = "rfc822name";
	private static final String EMAIL1 = "email";
	private static final String EMAIL2 = "EmailAddress";
	private static final String EMAIL3 = "E";
	private static final String[] EMAILIDS = { EMAIL, EMAIL1, EMAIL2, EMAIL3 };
	private static final String DNS = "dNSName";
	private static final String URI = "uniformResourceIdentifier";
	private static final String URI1 = "uri";
	private static final String URI2 = "uniformResourceId";
	private static final String IPADDR = "iPAddress";
	private static final String DIRECTORYNAME = "directoryName";
	private static final String REGISTEREDID = "registeredID";
	private static final String UPN = "upn";
	private static final String XMPPADDR = "xmppAddr";
	private static final String SRVNAME = "srvName";
	private static final String FASCN = "fascN";
	private static final String PERMANENTIDENTIFIER = "permanentIdentifier";

	/** ObjectID for upn altName for windows smart card logon */
	private static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
	/** ObjectID for XmppAddr, rfc6120#section-13.7.1.4 */
	private static final String XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
	/** ObjectID for srvName, rfc4985 */
	private static final String SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
	private static final String FASCN_OBJECTID = "2.16.840.1.101.3.6.6";
	private static final String PERMANENTIDENTIFIER_OBJECTID = "1.3.6.1.5.5.7.8.3";
	private static final String PERMANENTIDENTIFIER_SEP = "/";

	/** Microsoft altName for windows domain controller guid */
	private static final String GUID = "guid";
	/** ObjectID for upn altName for windows domain controller guid */
	private static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";

	/** OID for Kerberos altName for smart card logon */
	private static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";

	/** Label for SIM rendered in the certificate. */
	private static final String SUBJECTIDENTIFICATIONMETHOD = "subjectIdentificationMethod";
	/** OID for SIM written into the certificate. */
	private static final String SUBJECTIDENTIFICATIONMETHOD_OBJECTID = "1.3.6.1.5.5.7.8.6";
	/**
	 * List separator to separate the SIM tokens in the internal storage format
	 * (also has to be entered by the user).
	 */
	private static final String RFC4638_LIST_SEPARATOR = "::";

	private static final Pattern VALID_IPV4_PATTERN = Pattern.compile(
			"(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])", Pattern.CASE_INSENSITIVE);
	private static final Pattern VALID_IPV6_PATTERN = Pattern.compile(
			"(([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}|[0-9a-f]{1,4}(:[0-9a-f]{1,4})*::[0-9a-f]{1,4}(:[0-9a-f]{1,4})*)",
			Pattern.CASE_INSENSITIVE);

	private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
	private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

	public static GeneralNames getGeneralNamesFromAltName(final String altName) {
		if (log.isTraceEnabled()) {
			log.trace(">getGeneralNamesFromAltName: " + altName);
		}
		final ASN1EncodableVector vec = new ASN1EncodableVector();

		for (final String email : getEmailFromDN(altName)) {
			vec.add(new GeneralName(1, /* new DERIA5String(iter.next()) */email));
		}

		for (final String dns : getPartsFromDN(altName, DNS)) {
			vec.add(new GeneralName(2, new DERIA5String(dns)));
		}

		final String directoryName = getDirectoryStringFromAltName(altName);
		if (directoryName != null) {
			final X500Name x500DirectoryName = new X500Name(CeSecoreNameStyle.INSTANCE, directoryName);
			final GeneralName gn = new GeneralName(4, x500DirectoryName);
			vec.add(gn);
		}

		for (final String uri : getPartsFromDN(altName, URI)) {
			vec.add(new GeneralName(6, new DERIA5String(uri)));
		}
		for (final String uri : getPartsFromDN(altName, URI1)) {
			vec.add(new GeneralName(6, new DERIA5String(uri)));
		}
		for (final String uri : getPartsFromDN(altName, URI2)) {
			vec.add(new GeneralName(6, new DERIA5String(uri)));
		}

		for (final String addr : getPartsFromDN(altName, IPADDR)) {
			final byte[] ipoctets = ipStringToOctets(addr);
			if (ipoctets.length > 0) {
				final GeneralName gn = new GeneralName(7, new DEROctetString(ipoctets));
				vec.add(gn);
			} else {
				log.error("Cannot parse/encode ip address, ignoring: " + addr);
			}
		}
		for (final String oid : getPartsFromDN(altName, REGISTEREDID)) {
			vec.add(new GeneralName(GeneralName.registeredID, oid));
		}

		// UPN is an OtherName see method getUpn... for asn.1 definition
		for (final String upn : getPartsFromDN(altName, UPN)) {
			final ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(new ASN1ObjectIdentifier(UPN_OBJECTID));
			v.add(new DERTaggedObject(true, 0, new DERUTF8String(upn)));
			vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
		}

		// XmpAddr is an OtherName see method getUTF8String...... for asn.1 definition
		for (final String xmppAddr : getPartsFromDN(altName, XMPPADDR)) {
			final ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(new ASN1ObjectIdentifier(XMPPADDR_OBJECTID));
			v.add(new DERTaggedObject(true, 0, new DERUTF8String(xmppAddr)));
			vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
		}

		// srvName is an OtherName see method getIA5String...... for asn.1 definition
		for (final String srvName : getPartsFromDN(altName, SRVNAME)) {
			final ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(new ASN1ObjectIdentifier(SRVNAME_OBJECTID));
			v.add(new DERTaggedObject(true, 0, new DERIA5String(srvName)));
			vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
		}

		// FASC-N is an OtherName see method getOctetString...... for asn.1 definition
		// (PIV FIPS 201-2)
		// We take the input as being a hex encoded octet string
		for (final String fascN : getPartsFromDN(altName, FASCN)) {
			final ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(new ASN1ObjectIdentifier(FASCN_OBJECTID));
			v.add(new DERTaggedObject(true, 0, new DEROctetString(Hex.decode(fascN))));
			vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
		}

		// PermanentIdentifier is an OtherName see method getPermananentIdentifier...
		// for asn.1 definition
		for (final String permanentIdentifier : getPartsFromDN(altName, PERMANENTIDENTIFIER)) {
			final String[] values = getPermanentIdentifierValues(permanentIdentifier);
			final ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
			v.add(new ASN1ObjectIdentifier(PERMANENTIDENTIFIER_OBJECTID));
			// First the PermanentIdentifier sequence
			final ASN1EncodableVector piSeq = new ASN1EncodableVector();
			if (values[0] != null) {
				piSeq.add(new DERUTF8String(values[0]));
			}
			if (values[1] != null) {
				piSeq.add(new ASN1ObjectIdentifier(values[1]));
			}
			v.add(new DERTaggedObject(true, 0, new DERSequence(piSeq)));
			// GeneralName gn = new GeneralName(new DERSequence(v), 0);
			final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
			vec.add(gn);
		}

		for (final String guid : getPartsFromDN(altName, GUID)) {
			final ASN1EncodableVector v = new ASN1EncodableVector();
			final String dashRemovedGuid = guid.replace("-", "");
			byte[] guidbytes = Hex.decode(dashRemovedGuid);
			if (guidbytes != null) {
				v.add(new ASN1ObjectIdentifier(GUID_OBJECTID));
				v.add(new DERTaggedObject(true, 0, new DEROctetString(guidbytes)));
				final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
				vec.add(gn);
			} else {
				log.error("Cannot decode hexadecimal guid, ignoring: " + guid);
			}
		}

		// Krb5PrincipalName is an OtherName, see method getKrb5Principal...for ASN.1
		// definition
		for (final String principalString : getPartsFromDN(altName, KRB5PRINCIPAL)) {
			// Start by parsing the input string to separate it in different parts
			if (log.isDebugEnabled()) {
				log.debug("principalString: " + principalString);
			}
			// The realm is the last part moving back until an @
			final int index = principalString.lastIndexOf('@');
			String realm = "";
			if (index > 0) {
				realm = principalString.substring(index + 1);
			}
			if (log.isDebugEnabled()) {
				log.debug("realm: " + realm);
			}
			// Now we can have several principals separated by /
			final ArrayList<String> principalarr = new ArrayList<>();
			int jndex = 0;
			int bindex = 0;
			while (jndex < index) {
				// Loop and add all strings separated by /
				jndex = principalString.indexOf('/', bindex);
				if (jndex == -1) {
					jndex = index;
				}
				String s = principalString.substring(bindex, jndex);
				if (log.isDebugEnabled()) {
					log.debug("adding principal name: " + s);
				}
				principalarr.add(s);
				bindex = jndex + 1;
			}

			// Now we must construct the rather complex asn.1...
			final ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
			v.add(new ASN1ObjectIdentifier(KRB5PRINCIPAL_OBJECTID));

			// First the Krb5PrincipalName sequence
			final ASN1EncodableVector krb5p = new ASN1EncodableVector();
			// The realm is the first tagged GeneralString
			krb5p.add(new DERTaggedObject(true, 0, new DERGeneralString(realm)));
			// Second is the sequence of principal names, which is at tagged position 1 in
			// the krb5p
			final ASN1EncodableVector principals = new ASN1EncodableVector();
			// According to rfc4210 the type NT-UNKNOWN is 0, and according to some other
			// rfc this type should be used...
			principals.add(new DERTaggedObject(true, 0, new ASN1Integer(0)));
			// The names themselves are yet another sequence
			final ASN1EncodableVector names = new ASN1EncodableVector();
			for (final String principalName : principalarr) {
				names.add(new DERGeneralString(principalName));
			}
			principals.add(new DERTaggedObject(true, 1, new DERSequence(names)));
			krb5p.add(new DERTaggedObject(true, 1, new DERSequence(principals)));

			v.add(new DERTaggedObject(true, 0, new DERSequence(krb5p)));
			final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
			vec.add(gn);
		}

		// SIM is an OtherName. See RFC-4683
		for (final String internalSimString : getPartsFromDN(altName, SUBJECTIDENTIFICATIONMETHOD)) {
			if (StringUtils.isNotBlank(internalSimString)) {
				final String[] tokens = internalSimString.split(RFC4638_LIST_SEPARATOR);
				if (tokens.length == 3) {
					ASN1Primitive gn = createSimGeneralName(tokens[0], tokens[1], tokens[2]);
					vec.add(gn);
					if (log.isDebugEnabled()) {
						log.debug("SIM GeneralName added: " + gn.toString());
					}
				}
			}
		}

		// To support custom OIDs in altNames, they must be added as an OtherName of
		// plain type UTF8String
		for (final String oid : getCustomOids(altName)) {
			for (final String oidValue : getPartsFromDN(altName, oid)) {
				final ASN1EncodableVector v = new ASN1EncodableVector();
				v.add(new ASN1ObjectIdentifier(oid));
				v.add(new DERTaggedObject(true, 0, new DERUTF8String(oidValue)));
				final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
				vec.add(gn);
			}
		}

		if (vec.size() > 0) {
			return GeneralNames.getInstance(new DERSequence(vec));
		}
		return null;
	}

	/**
	 * Convenience method for getting an email addresses from a DN. Uses
	 * {@link #getPartsFromDN(String,String)} internally, and searches for
	 * {@link #EMAIL}, {@link #EMAIL1}, {@link #EMAIL2}, {@link #EMAIL3} and returns
	 * the first one found.
	 * 
	 * @param dn the DN
	 * 
	 * @return ArrayList containing email or empty list if email is not present
	 */
	private static List<String> getEmailFromDN(String dn) {
		if (log.isTraceEnabled()) {
			log.trace(">getEmailFromDN(" + dn + ")");
		}
		ArrayList<String> ret = new ArrayList<>();
		for (int i = 0; i < EMAILIDS.length; i++) {
			List<String> emails = getPartsFromDN(dn, EMAILIDS[i]);
			if (!emails.isEmpty()) {
				ret.addAll(emails);
			}

		}
		if (log.isTraceEnabled()) {
			log.trace("<getEmailFromDN(" + dn + "): " + ret.size());
		}
		return ret;
	}

	private static List<String> getPartsFromDN(final String dn, final String dnPart) {
		final List<String> parts = new ArrayList<>();
		if (dn != null && dnPart != null) {
			final String dnPartLowerCase = dnPart.toLowerCase();
			final int dnPartLenght = dnPart.length();
			boolean quoted = false;
			boolean escapeNext = false;
			int currentStartPosition = -1;
			for (int i = 0; i < dn.length(); i++) {
				final char current = dn.charAt(i);
				// Toggle quoting for every non-escaped "-char
				if (!escapeNext && current == '"') {
					quoted = !quoted;
				}
				// If there is an unescaped and unquoted =-char we need to investigate if it is
				// a match for the sought after part
				if (!quoted && !escapeNext && current == '=' && dnPartLenght <= i) {
					// Check that the character before our expected partName isn't a letter (e.g.
					// dnsName=.. should not match E=..)
					if (i - dnPartLenght - 1 < 0 || !Character.isLetter(dn.charAt(i - dnPartLenght - 1))) {
						boolean match = true;
						for (int j = 0; j < dnPartLenght; j++) {
							if (Character.toLowerCase(dn.charAt(i - dnPartLenght + j)) != dnPartLowerCase.charAt(j)) {
								match = false;
								break;
							}
						}
						if (match) {
							currentStartPosition = i + 1;
						}
					}
				}
				// When we have found a start marker, we need to be on the lookout for the
				// ending marker
				if (currentStartPosition != -1
						&& ((!quoted && !escapeNext && (current == ',' || current == '+')) || i == dn.length() - 1)) {
					int endPosition = (i == dn.length() - 1) ? dn.length() - 1 : i - 1;
					// Remove white spaces from the end of the value
					while (endPosition > currentStartPosition && dn.charAt(endPosition) == ' ') {
						endPosition--;
					}
					// Remove white spaces from the beginning of the value
					while (endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
						currentStartPosition++;
					}
					// Only return the inner value if the part is quoted
					if (currentStartPosition != dn.length() && dn.charAt(currentStartPosition) == '"'
							&& dn.charAt(endPosition) == '"') {
						currentStartPosition++;
						endPosition--;
					}
					parts.add(unescapeFieldValue(dn.substring(currentStartPosition, endPosition + 1)));
					currentStartPosition = -1;
				}
				if (escapeNext) {
					// This character was escaped, so don't escape the next one
					escapeNext = false;
				} else {
					if (!quoted && current == '\\') {
						// This escape character is not escaped itself, so the next one should be
						escapeNext = true;
					}
				}
			}
		}
		return parts;
	}

	/**
	 * Unescapes a value of a field in a DN, SAN or directory attributes.
	 * 
	 * @param value Value to unescape
	 * @return Unescaped string
	 */
	private static String unescapeFieldValue(final String value) {
		final Pattern unescapeFieldRegex = Pattern.compile("\\\\([,+\"\\\\<>; ])");
		if (value == null) {
			return null;
		} else {
			return unescapeFieldRegex.matcher(value).replaceAll("$1");
		}
	}

	/**
	 * Converts an IP-address string to octets of binary ints. ipv4 is of form
	 * a.b.c.d, i.e. at least four octets for example 192.168.5.54 ipv6 is of form
	 * a:b:c:d:e:f:g:h, for example 2001:0db8:85a3:0000:0000:8a2e:0370:7334
	 *
	 * Result is tested with openssl, that it's subjectAltName displays as intended.
	 *
	 * @param str string form of ip-address
	 * @return octets, empty array if input format is invalid, never null
	 */
	private static byte[] ipStringToOctets(final String str) {
		byte[] ret = null;
		if (isIpAddress(str)) {
			try {
				final InetAddress adr = InetAddress.getByName(str);
				ret = adr.getAddress();
			} catch (UnknownHostException e) {
				log.info("Error parsing ip address (ipv4 or ipv6): ", e);
			}
		}
		if (ret == null) {
			log.info("Not a IPv4 or IPv6 address, returning empty array.");
			ret = new byte[0];
		}
		return ret;
	}

	/**
	 * Determine if the given string is a valid IPv4 or IPv6 address. This method
	 * uses pattern matching to see if the given string could be a valid IP address.
	 * Snitched from
	 * http://www.java2s.com/Code/Java/Network-Protocol/DetermineifthegivenstringisavalidIPv4orIPv6address.htm
	 * Under LGPLv2 license.
	 *
	 * @param ipAddress A string that is to be examined to verify whether or not it
	 *                  could be a valid IP address.
	 * @return <code>true</code> if the string is a value that is a valid IP
	 *         address, <code>false</code> otherwise.
	 */
	private static boolean isIpAddress(final String ipAddress) {
		Matcher m1 = VALID_IPV4_PATTERN.matcher(ipAddress);
		if (m1.matches()) {
			return true;
		}
		Matcher m2 = VALID_IPV6_PATTERN.matcher(ipAddress);
		return m2.matches();
	}

	/**
	 * Obtain the directory string for the directoryName generation form the Subject
	 * Alternative Name String.
	 * 
	 * @param altName
	 * @return
	 */
	private static String getDirectoryStringFromAltName(final String altName) {
		List<String> partsFromDn = getPartsFromDN(altName, DIRECTORYNAME);
		String directoryName = (partsFromDn.size() > 0 ? partsFromDn.get(0) : null);
		return (StringUtils.isEmpty(directoryName) ? null : directoryName);
	}

	/**
	 * @param permanentIdentifierString
	 * @return A two elements String array with the extension values
	 */
	private static String[] getPermanentIdentifierValues(String permanentIdentifierString) {
		String[] result = new String[2];
		int sepPos = permanentIdentifierString.lastIndexOf(PERMANENTIDENTIFIER_SEP);
		if (sepPos == -1) {
			if (!permanentIdentifierString.isEmpty()) {
				result[0] = permanentIdentifierString.replace("\\" + PERMANENTIDENTIFIER, PERMANENTIDENTIFIER);
			}
		} else if (sepPos == 0) {
			if (permanentIdentifierString.length() > 1) {
				result[1] = permanentIdentifierString.substring(1);
			}
		} else if (permanentIdentifierString.charAt(sepPos - PERMANENTIDENTIFIER_SEP.length()) != '\\') {
			result[0] = permanentIdentifierString.substring(0, sepPos).replace("\\" + PERMANENTIDENTIFIER,
					PERMANENTIDENTIFIER);
			if (permanentIdentifierString.length() > sepPos + PERMANENTIDENTIFIER_SEP.length()) {
				result[1] = permanentIdentifierString.substring(sepPos + 1);
			}
		}
		return result;
	}

	/**
	 * Creates a SIM GeneralName by the internal SIM storage format
	 * ('hashAlgorithmOIDString::R::PEPSI') SIM ::= SEQUENCE { hashAlg
	 * AlgorithmIdentifier, authorityRandom OCTET STRING, -- RA-chosen random number
	 * -- used in computation of -- pEPSI pEPSI OCTET STRING -- hash of HashContent
	 * -- with algorithm hashAlg }
	 * 
	 * @param hashAlogrithmOidString the OID string for the hash algorithm used to
	 *                               hash R and PEPSI.
	 * @param authorityRandom        the registration authority chosen random value,
	 *                               hashed with hash of hashAlogrithmOidString (see
	 *                               https://tools.ietf.org/html/rfc4683#section-4.3).
	 * @param pepsi                  Privacy-Enhanced Protected Subject Information
	 *                               (PEPSI), with SIM = R || PEPSI.
	 * @return the RFC4683 SIM GeneralName (see
	 *         <a href="https://tools.ietf.org/html/rfc4683#section-4.3">RFC 4683
	 *         section 4.3</a>).
	 */
	private static final ASN1Primitive createSimGeneralName(final String hashAlgorithmIdentifier,
			final String authorityRandom, final String pepsi) {
		final ASN1EncodableVector otherName = new ASN1EncodableVector();
		otherName.add(new ASN1ObjectIdentifier(SUBJECTIDENTIFICATIONMETHOD_OBJECTID));
		final ASN1EncodableVector simVector = new ASN1EncodableVector();
		simVector.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashAlgorithmIdentifier)));
		simVector.add(new DEROctetString((authorityRandom).getBytes()));
		simVector.add(new DEROctetString((pepsi).getBytes()));
		otherName.add(new DERTaggedObject(true, 0, new DERSequence(simVector)));
		final ASN1Primitive generalName = new DERTaggedObject(false, 0, new DERSequence(otherName));

		return generalName;
	}

	public static PKCS10CertificationRequest generateCertificateRequest(final X500Name userDN,
			final String subjectAltName, final PublicKey publicKey, final PrivateKey privateKey) throws IOException {
		// Add an altName extension
		ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
		if (!StringUtils.isBlank(subjectAltName)) {
			GeneralNames san = getGeneralNamesFromAltName(subjectAltName);
			extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, san);
		}
		final Extensions extensions = extensionsGenerator.generate();
		// Add the extension(s) to the PKCS#10 request as a pkcs_9_at_extensionRequest
		ASN1EncodableVector extensionattr = new ASN1EncodableVector();
		extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		extensionattr.add(new DERSet(extensions));
		// Complete the Attribute section of the request, the set (Attributes) contains
		// one sequence (Attribute)
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERSequence(extensionattr));
		DERSet attributes = new DERSet(v);
		try {
			return genPKCS10CertificationRequest("SHA256WithRSA", userDN, publicKey, attributes, privateKey);
		} catch (OperatorCreationException e) {
			log.error("Unable to generate CSR: " + e.getLocalizedMessage());
			return null;
		}

	}

	public static PKCS10CertificationRequest genPKCS10CertificationRequest(String signatureAlgorithm, X500Name subject,
			PublicKey publickey, ASN1Set attributes, PrivateKey privateKey) throws OperatorCreationException {

		ContentSigner signer;
		CertificationRequestInfo reqInfo;
		try {
			SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publickey.getEncoded());
			reqInfo = new CertificationRequestInfo(subject, pkinfo, attributes);

			signer = new BufferingContentSigner(new JcaContentSignerBuilder(signatureAlgorithm)
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey), 20480);
			signer.getOutputStream().write(reqInfo.getEncoded(ASN1Encoding.DER));
			signer.getOutputStream().flush();
		} catch (IOException e) {
			throw new IllegalStateException("Unexpected IOException was caught.", e);
		}
		byte[] sig = signer.getSignature();
		DERBitString sigBits = new DERBitString(sig);

		CertificationRequest req = new CertificationRequest(reqInfo, signer.getAlgorithmIdentifier(), sigBits);
		return new PKCS10CertificationRequest(req);
	}

	/**
	 * Gets a list of all custom OIDs defined in the string. A custom OID is defined
	 * as an OID, simply as that. Otherwise, if it is not a custom oid, the DNpart
	 * is defined by a name such as CN och rfc822Name. This method only returns a
	 * oid once, so if the input string has multiple of the same oid, only one value
	 * is returned.
	 * 
	 * @param dn String containing DN, The DN string has the format "C=SE, O=xx,
	 *           OU=yy, CN=zz", or "rfc822Name=foo@bar.com", etc.
	 * @param dn String specifying which part of the DN to get, should be "CN" or
	 *           "OU" etc.
	 * 
	 * @return ArrayList containing unique oids or empty list if no custom OIDs are
	 *         present
	 */
	private static List<String> getCustomOids(String dn) {
		if (log.isTraceEnabled()) {
			log.trace(">getCustomOids: dn:'" + dn);
		}
		List<String> parts = new ArrayList<>();
		if (dn != null) {
			String o;
			X509NameTokenizer xt = new X509NameTokenizer(dn);
			while (xt.hasMoreTokens()) {
				o = xt.nextToken().trim();
				// Try to see if it is a valid OID
				try {
					int i = o.indexOf('=');
					// An oid is never shorter than 3 chars and must start with 1.
					if ((i > 2) && (o.charAt(1) == '.')) {
						String oid = o.substring(0, i);
						// If we have multiple of the same custom oid, don't claim that we have more
						// This method will only return "unique" custom oids.
						if (!parts.contains(oid)) {
							// Check if it is a real oid, if it is not we will ignore it
							// (IllegalArgumentException will be thrown)
							new ASN1ObjectIdentifier(oid);
							parts.add(oid);
						}
					}
				} catch (IllegalArgumentException e) {
					// Not a valid oid
				}
			}
		}
		if (log.isTraceEnabled()) {
			log.trace("<getCustomOids: resulting DN part=" + parts.toString());
		}
		return parts;
	}

	/**
	 * Creates Certificate from byte[], can be either an X509 certificate or a
	 * CVCCertificate
	 * 
	 * @param cert byte array containing certificate in binary (DER) format or PEM
	 *             encoded X.509 certificate
	 * 
	 * @return a Certificate
	 * @throws CertificateParsingException if certificate couldn't be parsed from
	 *                                     cert, or if the incorrect return type was
	 *                                     specified.
	 * 
	 */
	public static X509Certificate getCertfromByteArray(final byte[] cert) throws CertificateParsingException {

		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CertificateParsingException("Could not create certificate factory", e);
		}
		X509Certificate result;
		try {
			result = (X509Certificate) certificateFactory
					.generateCertificate(new SecurityFilterInputStream(new ByteArrayInputStream(cert)));
		} catch (CertificateException e) {
			throw new CertificateParsingException(
					"Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
		}
		if (result != null) {
			return result;
		} else {
			throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
		}
	}



	/**
	 * Returns a certificate in PEM-format.
	 * 
	 * @param certs Collection of Certificate to convert to PEM
	 * @return byte array containing PEM certificate
	 */
	public static byte[] getPemFromCertificate(X509Certificate certificate) {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (final PrintStream printStream = new PrintStream(baos)) {

			if (certificate != null) {
				printStream.println("Subject: " + certificate.getSubjectDN().toString());
				printStream.println("Issuer: " + certificate.getIssuerDN().toString());
				writeAsPemEncoded(printStream, certificate.getEncoded(), BEGIN_CERTIFICATE, END_CERTIFICATE);
			}

		} catch (CertificateEncodingException e) {
			throw new IllegalStateException("Certificate encoding exception encountered.", e);
		}
		return baos.toByteArray();
	}

	/**
	 * Write the supplied bytes to the printstream as Base64 using beginKey and
	 * endKey around it.
	 */
	private static void writeAsPemEncoded(PrintStream printStream, byte[] unencodedData, String beginKey,
			String endKey) {
		printStream.println(beginKey);
		printStream.println(new String(Base64.encode(unencodedData)));
		printStream.println(endKey);
	}
	
    /**
     * Reads certificates in PEM-format from a filename.
     * The stream may contain other things between the different certificates.
     * 
     * @param certificateFilename filename of the file containing the certificates in PEM-format
     * @param returnType a Class specifying the desired return type. Certificate can be used if return type is unknown.
     * 
     * @return Ordered List of Certificates, first certificate first, or empty List
     * @throws FileNotFoundException if certFile was not found
     * @throws CertificateParsingException if the file contains an incorrect certificate.
     */
    public static List<X509Certificate> getCertsFromPEM(final String certificateFilename) throws FileNotFoundException, CertificateParsingException {
  
        final List<X509Certificate> certs;
        try (final InputStream inStrm = new FileInputStream(certificateFilename)) {
            certs = getCertsFromPEM(inStrm);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to close input stream");
        }
        return certs;
    }
    
    /**
     * Reads certificates in PEM-format from an InputStream. 
     * The stream may contain other things between the different certificates.
     * 
     * @param certstream the input stream containing the certificates in PEM-format
     * @param returnType specifies the desired certificate type. Certificate can be used if certificate type is unknown.
     * @return Ordered List of Certificates, first certificate first, or empty List
     * @exception CertificateParsingException if the stream contains an incorrect certificate.
     */
    public static List<X509Certificate> getCertsFromPEM(final InputStream certstream) throws CertificateParsingException {
        final List<X509Certificate> ret = new ArrayList<>();
        final String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
        final String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
        try (final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(new SecurityFilterInputStream(certstream)))) {
            while (bufRdr.ready()) {
                final ByteArrayOutputStream ostr = new ByteArrayOutputStream();
                final PrintStream opstr = new PrintStream(ostr);
                String temp;
                while ((temp = bufRdr.readLine()) != null && !(temp.equals(BEGIN_CERTIFICATE) || temp.equals(beginKeyTrust))) {
                    continue;
                }
                if (temp == null) {
                    if (ret.isEmpty()) {
                        // There was no certificate in the file
                        throw new CertificateParsingException("Error in " + certstream.toString() + ", missing " + BEGIN_CERTIFICATE
                                + " boundary");
                    } else {
                        // There were certificates, but some blank lines or something in the end
                        // anyhow, the file has ended so we can break here.
                        break;
                    }
                }
                while ((temp = bufRdr.readLine()) != null && !(temp.equals(END_CERTIFICATE) || temp.equals(endKeyTrust))) {
                    opstr.print(temp);
                }
                if (temp == null) {
                    throw new IllegalArgumentException("Error in " + certstream.toString() + ", missing " + END_CERTIFICATE
                            + " boundary");
                }
                opstr.close();

                byte[] certbuf = Base64.decode(ostr.toByteArray());
                ostr.close();
                // Phweeew, were done, now decode the cert from file back to Certificate object
                X509Certificate cert = getCertfromByteArray(certbuf);
                ret.add(cert);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Exception caught when attempting to read stream, see underlying IOException", e);
        }
        return ret;
    }
    
    /**
     * Gets Serial number of the certificate as a string. For X509 Certificate this means a HEX encoded BigInteger.
     * 
     * For X509 certificates, the value is normalized (uppercase without leading zeros), so there's no need to normalize the returned value.
     * 
     */
    public static String getSerialNumberAsString(final X509Certificate certficate) {
        if (certficate == null) {
            throw new IllegalArgumentException("Certificate was null.");
        }
        return certficate.getSerialNumber().toString(16).toUpperCase();
    }
	
}
