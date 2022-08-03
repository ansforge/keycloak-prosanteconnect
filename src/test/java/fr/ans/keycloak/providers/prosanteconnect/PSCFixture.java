package fr.ans.keycloak.providers.prosanteconnect;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

import fr.ans.keycloak.providers.prosanteconnect.PSCEnvironment;
import fr.ans.keycloak.providers.prosanteconnect.ProSanteConnectIdentityProviderConfig;
import fr.ans.keycloak.utils.PublicKeysStore;
import fr.ans.keycloak.utils.SignatureUtils;

import static fr.ans.keycloak.utils.KeycloakFixture.CLIENT_ID;
import static fr.ans.keycloak.utils.KeycloakFixture.CLIENT_SECRET;
import static fr.ans.keycloak.utils.SignatureUtils.*;

import org.keycloak.models.IdentityProviderModel;

final class PSCFixture {

  private PSCFixture() {
  }

  static final JWTClaimsSet EIDAS1_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.bas.psc.esante.gouv.fr/auth/realms/esante-wallet")
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
      .issuer("https://auth.bas.psc.esante.gouv.fr/auth/realms/esante-wallet")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "PSC")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet UNSUPPORTED_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.bas.psc.esante.gouv.fr/auth/realms/esante-wallet")
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
