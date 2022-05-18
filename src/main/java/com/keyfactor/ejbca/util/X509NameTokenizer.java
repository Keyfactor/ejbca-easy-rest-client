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

/**
 * class for breaking up an X500 Name into it's component tokens, ala
 * java.util.StringTokenizer.
 */
public class X509NameTokenizer {
	private String value;
	private int index;
	private char separator;
	private StringBuffer buf = new StringBuffer();

	/**
	 * Creates the object, using the default comma (,) as separator for tokenization
	 */
	public X509NameTokenizer(String oid) {
		this(oid, ',');
	}

	public X509NameTokenizer(String oid, char separator) {
		this.value = oid;
		this.index = -1;
		this.separator = separator;
	}

	public boolean hasMoreTokens() {
		return (value != null && index != value.length());
	}

	public String nextToken() {
		if (index == value.length()) {
			return null;
		}
		int end = index + 1;
		boolean quoted = false;
		boolean escaped = false;
		buf.setLength(0);
		while (end != value.length()) {
			char c = value.charAt(end);

			if (c == '"') {
				if (!escaped) {
					quoted = !quoted;
				} else {
					if (c == '#' && buf.charAt(buf.length() - 1) == '=') {
						buf.append('\\');
					} else if (c == '+' && separator != '+') {
						buf.append('\\');
					}
					buf.append(c);
				}
				escaped = false;
			} else {
				if (escaped || quoted) {
					if (c == '#' && buf.charAt(buf.length() - 1) == '=') {
						buf.append('\\');
					} else if (c == '+' && separator != '+') {
						buf.append('\\');
					}
					buf.append(c);
					escaped = false;
				} else if (c == '\\') {
					escaped = true;
				} else if (c == separator) {
					break;
				} else {
					buf.append(c);
				}
			}
			end++;
		}
		index = end;
		return buf.toString().trim();
	}
}