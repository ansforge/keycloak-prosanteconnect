/*
 * MIT License
 *
 * Copyright (c) 2022-2024 Agence du Numérique en Santé
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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

  static final PSCEnvironment DEFAULT_PSC_ENVIRONMENT = PSCEnvironment.PRODUCTION;
  
  static final String EMAIL = "email";

  static final List<IdentityProviderMapperModel> PSC_PROVIDER_MAPPERS = List.of(
      createUserAttributeMapper(PSC_PROVIDER_ID, "lastName", "family_name", "lastName"),
      createUserAttributeMapper(PSC_PROVIDER_ID, "firstName", "given_name", "firstName"),
      createUserAttributeMapper(PSC_PROVIDER_ID, EMAIL, EMAIL, EMAIL),
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
