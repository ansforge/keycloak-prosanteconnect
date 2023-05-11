/*
 * (c) Copyright 1998-2023, ANS. All rights reserved.
 */
package fr.ans.keycloak.mappers;

import fr.ans.keycloak.providers.prosanteconnect.ProSanteConnectIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

public final class ProSanteConnectUserAttributeMapper extends UserAttributeMapper {

  public static final String MAPPER_NAME = "psc-user-attribute-mapper";

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
