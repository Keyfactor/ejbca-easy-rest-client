/**
 * 
 */
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
