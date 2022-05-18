/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.library.CommandLibrary;

/**
 *
 */
public class ErceClient {


	public static void main(String[] args) {
        if (args.length == 0 || !CommandLibrary.INSTANCE.doesCommandExist(args)) {
            CommandLibrary.INSTANCE.listRootCommands();           
        } else {
        	Security.addProvider(new BouncyCastleProvider());
            CommandResult result = CommandLibrary.INSTANCE.findAndExecuteCommandFromParameters(args);
            if(result != CommandResult.SUCCESS) {
                System.exit(result.getReturnCode());
            }
        }
    }

}
