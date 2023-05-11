/*
 * (c) Copyright 1998-2023, ANS. All rights reserved.
 */
package fr.ans.keycloak.mappers;

import fr.ans.keycloak.providers.prosanteconnect.ProSanteConnectIdentityProviderFactory;

import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public final class ProSanteConnectUsernameTemplateMapper extends UsernameTemplateMapper {

  public static final String MAPPER_NAME = "psc-username-template-mapper";

  private static final String[] COMPATIBLE_PROVIDERS =
      new String[]{
          ProSanteConnectIdentityProviderFactory.PSC_PROVIDER_ID
      };

  @Override
  public String[] getCompatibleProviders() {
    return COMPATIBLE_PROVIDERS;
  }

  @Override
  public String getId() {
    return MAPPER_NAME;
  }
}
