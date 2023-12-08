/*
 * MIT License
 *
 * Copyright (c) 2022-2023 Agence du Numérique en Santé
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

import static fr.ans.keycloak.utils.KeycloakFixture.CLIENT_ID;
import static fr.ans.keycloak.utils.KeycloakFixture.CLIENT_SECRET;
import static fr.ans.keycloak.utils.SignatureUtils.generateES256Key;
import static fr.ans.keycloak.utils.SignatureUtils.signJwtWithES256PrivateKey;
import static fr.ans.keycloak.utils.SignatureUtils.signJwtWithHS256SharedSecret;

import org.keycloak.models.IdentityProviderModel;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

import fr.ans.keycloak.utils.PublicKeysStore;
import fr.ans.keycloak.utils.SignatureUtils;

final class PSCFixture {

  private PSCFixture() {
  }

  static final JWTClaimsSet EIDAS1_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.esw.esante.gouv.fr/auth/realms/esante-wallet")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "PSC")
      .claim("acr", "eidas1")
      .claim("amr", null)
      .build();

  /*static final JWTClaimsSet EIDAS2_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.integ01.dev-franceconnect.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "FC")
      .claim("acr", "eidas2")
      .claim("amr", null)
      .build();*/

  static final JWTClaimsSet NO_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.esw.esante.gouv.fr/auth/realms/esante-wallet")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "PSC")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet UNSUPPORTED_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.esw.esante.gouv.fr/auth/realms/esante-wallet")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "PSC")
      .claim("acr", "eidas2")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet USERINFO_JWT = new JWTClaimsSet.Builder()
      .claim("sub", "fakeSub")
      .claim("given_name", "John")
      .claim("family_name", "Doe")
      .claim("email", "john.doe@gmail.com")
      .build();

  /*static ProSanteConnectIdentityProviderConfig givenConfigForIntegrationAndEidasLevel2() {
    return givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas2");
  }*/

  static ProSanteConnectIdentityProviderConfig givenConfigWithSelectedEnvAndSelectedEidasLevel(String environmentName, String eidasLevelName) {
    var model = new IdentityProviderModel();
    model.getConfig().put(PSCEnvironment.ENVIRONMENT_PROPERTY_NAME, environmentName);
    model.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, eidasLevelName);
    model.getConfig().put("ignoreAbsentStateParameterLogout", "false");
    model.getConfig().put("clientId", CLIENT_ID);
    model.getConfig().put("clientSecret", CLIENT_SECRET);

    return new ProSanteConnectIdentityProviderConfig(model);
  }
  
  static ProSanteConnectIdentityProviderConfig givenDefaultConfig() {
	  return new ProSanteConnectIdentityProviderConfig();
  }

  static String givenAnHMACSignedEidas1JWT() {
    return signJwtWithHS256SharedSecret(EIDAS1_JWT, CLIENT_SECRET);
  }

  static String givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(String kid, PublicKeysStore publicKeysStore, RSAKey rsaKey) {
    return SignatureUtils.givenAnRSAOAEPJWE(
        rsaKey,
        SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS1_JWT, publicKeysStore)
    );
  }

  static String givenAnES256SignedJWTWithUnknownKidInJWKS() {
    var ecKey = generateES256Key("unknownKid");
    return signJwtWithES256PrivateKey(EIDAS1_JWT, ecKey);
  }
}
