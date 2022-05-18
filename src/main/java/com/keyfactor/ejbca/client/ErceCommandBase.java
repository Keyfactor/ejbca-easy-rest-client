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
package com.keyfactor.ejbca.client;

import org.ejbca.ui.cli.infrastructure.command.CommandBase;

/**
 *
 */
public abstract class ErceCommandBase extends CommandBase {

	@Override
	public String getImplementationName() {
		return "Erce: Easy REST Client for EJBCA";
	}

}
