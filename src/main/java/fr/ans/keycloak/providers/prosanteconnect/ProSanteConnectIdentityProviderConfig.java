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

import static fr.ans.keycloak.providers.prosanteconnect.ProSanteConnectIdentityProviderFactory.PSC_PROVIDER_MAPPERS;

import java.util.List;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

final class ProSanteConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String IS_CONFIG_CREATED_PROPERTY = "isCreated";

	ProSanteConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
		super(identityProviderModel);
		initialize();
	}

	ProSanteConnectIdentityProviderConfig() {
		super();
		initialize();
	}

	protected void initialize() {
		configureUrlsFromEnvironment();

		setValidateSignature(true);
		setBackchannelSupported(false);
	}

	protected void configureUrlsFromEnvironment() {
		setAuthorizationUrl(getEnvironmentProperty("authorization.url"));
		setTokenUrl(getEnvironmentProperty("token.url"));
		setUserInfoUrl(getEnvironmentProperty("userinfo.url"));
		setLogoutUrl(getEnvironmentProperty("logout.url"));
		setIssuer(getEnvironmentProperty("issuer.url"));

		var useJwks = getEnvironmentProperty("use.jwks.url");
		if (useJwks != null) {
			setJwksUrl(getEnvironmentProperty("jwks.url"));
			setUseJwksUrl(Boolean.parseBoolean(useJwks));
		}
	}

	protected String getEnvironmentProperty(String key) {
		var pscEnvironment = PSCEnvironment.PRODUCTION;
		String env = System.getenv("PROSANTECONNECT_BACASABLE");
		if(env != null && env.contentEquals("1")) {
			pscEnvironment = PSCEnvironment.INTEGRATION;
		}

		return pscEnvironment.getProperty(key);
	}

	protected List<IdentityProviderMapperModel> getDefaultMappers() {
		return PSC_PROVIDER_MAPPERS;
	}

	protected EidasLevel getDefaultEidasLevel() {
		return EidasLevel.EIDAS1;
	}

	public EidasLevel getEidasLevel() {
		return EidasLevel.getOrDefault(getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME), getDefaultEidasLevel());
	}

	@Override
	public void validate(RealmModel realm) {
		super.validate(realm);

		if (!isCreated()) {
			getDefaultMappers().forEach(realm::addIdentityProviderMapper);
			getConfig().put(IS_CONFIG_CREATED_PROPERTY, "true");
		}
	}

	private boolean isCreated() {
		return Boolean.parseBoolean(getConfig().get(IS_CONFIG_CREATED_PROPERTY));
	}

	public boolean isIgnoreAbsentStateParameterLogout() {
		return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
	}
}
