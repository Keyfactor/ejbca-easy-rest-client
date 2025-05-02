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

import com.keyfactor.ejbca.client.ErceCommandBase;

/**
 * Base class for ConfigDump commands
 */

public abstract class ConfigDumpCommandBase extends ErceCommandBase {

	private static final String MAINCOMMAND = "configdump";
	
	@Override
	public String[] getCommandPath() {
		return new String[] { MAINCOMMAND };
	}
	
}
