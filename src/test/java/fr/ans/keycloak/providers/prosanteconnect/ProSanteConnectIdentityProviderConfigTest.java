/*
 * (c) Copyright 1998-2023, ANS. All rights reserved.
 */
package fr.ans.keycloak.providers.prosanteconnect;

import static fr.ans.keycloak.providers.prosanteconnect.PSCFixture.givenConfigWithSelectedEnvAndSelectedEidasLevel;
import static fr.ans.keycloak.providers.prosanteconnect.ProSanteConnectIdentityProviderFactory.PSC_PROVIDER_MAPPERS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

@DisplayNameGeneration(ReplaceUnderscores.class)
class ProSanteConnectIdentityProviderConfigTest {

  @Test
  void should_initialize_config_with_selected_eidas_level_from_admin_interface() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS1);

    /*config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas2");

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS2);

    config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas3");

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS3);*/
  }

  @Test
  void
      should_initialize_config_with_url_properties_corresponding_to_selected_environment_from_admin_interface() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");

    assertThat(config.getAuthorizationUrl()).isNotNull().endsWith("/auth");
    assertThat(config.getTokenUrl()).isNotNull().endsWith("/token");
    assertThat(config.getUserInfoUrl()).isNotNull().endsWith("/userinfo");
    assertThat(config.getLogoutUrl()).isNotNull().endsWith("/logout");
    //assertThat(config.getIssuer()).isNotNull();
    //assertThat(config.isUseJwksUrl()).isTrue();
    //assertThat(config.getJwksUrl()).endsWith("/jwks");
  }

  @Test
  void
      should_initialize_config_with_selected_ignoreAbsentStateParameterLogout_from_admin_interface() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");;

    assertThat(config.isIgnoreAbsentStateParameterLogout()).isFalse();
  }

  @Test
  void should_initialize_config_with_signature_validation() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");;

    assertThat(config.isValidateSignature()).isTrue();
  }

  @Test
  void should_initialize_config_without_backchannel_support() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");;

    assertThat(config.isBackchannelSupported()).isFalse();
  }

  @Test
  void should_create_identity_mappers_when_saving_configuration_for_the_first_time() {
    var unsavedConfig = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");;
    var realm = mock(RealmModel.class);

    unsavedConfig.validate(realm);

    verify(realm, times(PSC_PROVIDER_MAPPERS.size())).addIdentityProviderMapper(any());

    var alreadySavedConfig = givenConfigWithSelectedEnvAndSelectedEidasLevel("integration", "eidas1");;
    var unusedRealm = mock(RealmModel.class);
    alreadySavedConfig.getConfig().put("isCreated", "true");

    alreadySavedConfig.validate(unusedRealm);

    verify(unusedRealm, never()).addIdentityProviderMapper(any());
  }
}
