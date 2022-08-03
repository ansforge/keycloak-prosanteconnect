package fr.ans.keycloak.providers.prosanteconnect;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import static fr.ans.keycloak.providers.prosanteconnect.Utils.createHardcodedAttributeMapper;
import static fr.ans.keycloak.providers.prosanteconnect.Utils.createUserAttributeMapper;

import java.util.List;

public final class ProSanteConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<ProSanteConnectIdentityProvider>
    implements SocialIdentityProviderFactory<ProSanteConnectIdentityProvider> {

  public static final String PSC_PROVIDER_ID = "psc";
  public static final String PSC_PROVIDER_NAME = "Pro Sante Connect";

  static final PSCEnvironment DEFAULT_PSC_ENVIRONMENT = PSCEnvironment.INTEGRATION;

  static final List<IdentityProviderMapperModel> PSC_PROVIDER_MAPPERS = List.of(
      createUserAttributeMapper(PSC_PROVIDER_ID, "lastName", "family_name", "lastName"),
      createUserAttributeMapper(PSC_PROVIDER_ID, "firstName", "given_name", "firstName"),
      createUserAttributeMapper(PSC_PROVIDER_ID, "email", "email", "email"),
      createHardcodedAttributeMapper(PSC_PROVIDER_ID, "provider", "provider", "PSC")
  );

  @Override
  public String getName() {
    return PSC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return PSC_PROVIDER_ID;
  }

  @Override
  public ProSanteConnectIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new ProSanteConnectIdentityProvider(session, new ProSanteConnectIdentityProviderConfig(model));
  }

  @Override
  public ProSanteConnectIdentityProviderConfig createConfig() {
    return new ProSanteConnectIdentityProviderConfig();
  }
}
