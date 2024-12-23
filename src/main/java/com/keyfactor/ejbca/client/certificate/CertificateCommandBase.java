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
package com.keyfactor.ejbca.client.certificate;

import com.keyfactor.ejbca.client.ErceCommandBase;

/**
 * Base class for all search related commands
 */

public abstract class CertificateCommandBase extends ErceCommandBase {

	private final String MAIN_COMMAND = "certificate";
	
	@Override
	public String getMainCommand() {
		return MAIN_COMMAND;
	}

	@Override
	public String[] getCommandPath() {
		return new String[] { MAIN_COMMAND };
	}

}
