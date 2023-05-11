/*
 * (c) Copyright 1998-2023, ANS. All rights reserved.
 */
package fr.ans.keycloak.providers.prosanteconnect;

public class KeycloakPscRuntimeException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
	public KeycloakPscRuntimeException(String errorMessage) {
		super(errorMessage);
	}

	public KeycloakPscRuntimeException(String errorMessage, Throwable err) {
		super(errorMessage, err);
	}
	
}
