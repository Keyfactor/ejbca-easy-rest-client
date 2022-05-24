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

package com.keyfactor.ejbca.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class AlgorithmTools {

	private static final Logger log = Logger.getLogger(AlgorithmTools.class);
	
	public static Map<String, List<String>> preProcessCurveNames() {
		final Map<String, List<String>> processedCurveNames = new HashMap<>();
		Set<ECNamedCurveParameterSpec> addedCurves = new HashSet<>();
		final Enumeration<?> ecNamedCurvesStandard = ECNamedCurveTable.getNames();
		// Process standard curves, removing blacklisted ones and those not supported by
		// the provider
		while (ecNamedCurvesStandard.hasMoreElements()) {
			final String ecNamedCurve = (String) ecNamedCurvesStandard.nextElement();
			final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(ecNamedCurve);

			if (addedCurves.contains(parameterSpec)) {
				// Check if this param spec exists under another alias
				continue;
			}

			if (isNamedECKnownInDefaultProvider(ecNamedCurve)) {
				processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
			}

		}
		return processedCurveNames;

	}
	
    /** Check if the curve name is known by the first found PKCS#11 provider or default (BC) (if no EC capable PKCS#11 provider were found)*/
    private static boolean isNamedECKnownInDefaultProvider(String ecNamedCurveBc) {
        final Provider[] providers = Security.getProviders("KeyPairGenerator.EC");
        String providerName = providers[0].getName();
        try {
            for (Provider ecProvider : providers) {
                //This will list something like: SunPKCS11-NSS, BC, SunPKCS11-<library>-slot<slotnumber>
                if (ecProvider.getName().startsWith("SunPKCS11-") && !ecProvider.getName().startsWith("SunPKCS11-NSS") ) {
                    // Sometimes the P11 provider will not even know about EC, skip these providers. As an example the SunP11
                    // provider in some version/installations will throw a:
                    // java.lang.RuntimeException: Cannot load SunEC provider
                    //   at sun.security.pkcs11.P11ECKeyFactory.getSunECProvider(P11ECKeyFactory.java:55)
                    // This was a bug of non upgraded NSS in RHEL at some point in time.
                    try {
                        KeyPairGenerator.getInstance("EC", ecProvider.getName());
                        providerName = ecProvider.getName();
                        break;
                    } catch (RuntimeException e) {
                        log.info("Provider "+ecProvider.getName()+" bailed out on EC, ignored.", e);
                    }
                }
            }
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", providerName);
            kpg.initialize(new ECGenParameterSpec(getEcKeySpecOidFromBcName(ecNamedCurveBc)));
            return true;
        } catch (InvalidAlgorithmParameterException e) {
            if (log.isTraceEnabled()) {
                log.trace(ecNamedCurveBc + " is not available in provider " + providerName);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC capable provider " + providerName + " could no longer handle elliptic curve algorithm.." ,e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("EC capable provider " + providerName + " disappeard unexpectedly." ,e);
        }
        return false;
    }
	
	
	 /** @return a list of aliases for the provided curve name (including the provided name) */
    private static List<String> getEcKeySpecAliases(final String namedEllipticCurve) {
        final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(namedEllipticCurve);
        final List<String> ret = new ArrayList<>();
        ret.add(namedEllipticCurve);

        if (parameterSpec != null) { // GOST and DSTU aren't present in ECNamedCurveTable (and don't have aliases)
            final Enumeration<?> ecNamedCurves = ECNamedCurveTable.getNames();
            while (ecNamedCurves.hasMoreElements()) {
                final String currentCurve = (String) ecNamedCurves.nextElement();
                if (!namedEllipticCurve.equals(currentCurve)) {
                    final ECNamedCurveParameterSpec parameterSpec2 = ECNamedCurveTable.getParameterSpec(currentCurve);
                    if (parameterSpec.equals(parameterSpec2)) {
                        ret.add(currentCurve);
                    }
                }
            }
        }
        return ret;
    }
    
    /**
     * Convert from BC ECC curve names to the OID.
     *
     * @param ecNamedCurveBc the name as BC reports it
     * @return the OID of the curve or the input curve name if it is unknown by BC
     */
    private static String getEcKeySpecOidFromBcName(final String ecNamedCurveBc) {
        // Although the below class is in x9 package, it handles all different curves, including TeleTrust (brainpool)
        final ASN1ObjectIdentifier oid = org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(ecNamedCurveBc);
        if (oid==null) {
            return ecNamedCurveBc;
        }
        return oid.getId();
    }
}
