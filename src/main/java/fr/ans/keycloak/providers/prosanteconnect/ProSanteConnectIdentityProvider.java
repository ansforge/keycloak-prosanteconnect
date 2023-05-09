package fr.ans.keycloak.providers.prosanteconnect;

import static fr.ans.keycloak.providers.prosanteconnect.Utils.transcodeSignatureToDER;
import static javax.ws.rs.core.Response.Status.OK;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.bind.DatatypeConverter;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

final class ProSanteConnectIdentityProvider extends OIDCIdentityProvider
		implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

	private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";
	private static final MediaType APPLICATION_JWT_TYPE = MediaType.valueOf("application/jwt");

	protected static final String ACR_CLAIM_NAME = "acr";
	protected JSONWebKeySet jwks;

	@Override
	public ProSanteConnectIdentityProviderConfig getConfig() {
		return (ProSanteConnectIdentityProviderConfig) super.getConfig();
	}

	@Override
	public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
		return new OIDCEndpoint(callback, realm, event, getConfig(), this);
	}

	@Override
	public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession,
			UriInfo uriInfo, RealmModel realm) {

		var config = getConfig();

		var logoutUrl = config.getLogoutUrl();
		if (logoutUrl == null || logoutUrl.trim().equals("")) {
			return null;
		}

		var idToken = getIdTokenForLogout(userSession);

		if (config.isBackchannelSupported()) {
			backchannelLogout(userSession, idToken);
			return null;
		}

		var sessionId = userSession.getId();
		var logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);
		logoutUri.queryParam("id_token_hint", idToken);

		var redirectUri = RealmsResource.brokerUrl(uriInfo).path(IdentityBrokerService.class, "getEndpoint")
				.path(OIDCEndpoint.class, "logoutResponse").build(realm.getName(), config.getAlias()).toString();

		logoutUri.queryParam("post_logout_redirect_uri", redirectUri);

		return Response.status(Response.Status.FOUND).location(logoutUri.build()).build();
	}

	@Override
	protected boolean verify(JWSInput jws) {
		logger.info("Validating: " + jws.getWireString());

		var config = getConfig();
		var algorithm = JavaAlgorithm.getJavaAlgorithm(jws.getHeader().getAlgorithm().name());

		if (!config.isValidateSignature()) {
			return true;
		}

		if (algorithm.equals(JavaAlgorithm.HS256)) {
			try (var vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
				var clientSecret = vaultStringSecret.get().orElse(getConfig().getClientSecret());
				return HMACProvider.verify(jws, clientSecret.getBytes());
			}
		}

		try {
			var publicKey = Optional.ofNullable(JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.SIG).getKeys().stream()
					.collect(Collectors.toMap(KeyWrapper::getKid, keyWrapper -> (PublicKey) keyWrapper.getPublicKey()))
					.get(jws.getHeader().getKeyId())).or(() -> {
						// Try reloading jwks url
						jwks = Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session);
						return Optional.ofNullable(JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.SIG).getKeys().stream()
								.collect(Collectors.toMap(KeyWrapper::getKid,
										keyWrapper -> (PublicKey) keyWrapper.getPublicKey()))
								.get(jws.getHeader().getKeyId()));
					}).orElse(null);

			if (publicKey == null) {
				logger.error("No keys found for kid: " + jws.getHeader().getKeyId());
				return false;
			}

			var verifier = Signature.getInstance(algorithm);
			verifier.initVerify(publicKey);
			verifier.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8));

			var signature = jws.getSignature();
			if (algorithm.endsWith("ECDSA")) {
				signature = transcodeSignatureToDER(signature);
			}

			return verifier.verify(signature);
		} catch (Exception ex) {
			logger.error("Signature verification failed", ex);
			return false;
		}
	}

	@Override
	public BrokeredIdentityContext getFederatedIdentity(String response) {

		try {
			var federatedIdentity = super.getFederatedIdentity(response);

			var idToken = (JsonWebToken) federatedIdentity.getContextData().get(VALIDATED_ID_TOKEN);
			var acrClaim = (String) idToken.getOtherClaims().get(ACR_CLAIM_NAME);

			var fcReturnedEidasLevel = EidasLevel.getOrDefault(acrClaim, null);
			var expectedEidasLevel = getConfig().getEidasLevel();

			if (fcReturnedEidasLevel == null) {
				throw new IdentityBrokerException("The returned eIDAS level cannot be retrieved");
			}

			logger.debugv("Expecting eIDAS level: {0}, actual: {1}", expectedEidasLevel, fcReturnedEidasLevel);

			if (fcReturnedEidasLevel.compareTo(expectedEidasLevel) < 0) {
				throw new IdentityBrokerException("The returned eIDAS level is insufficient");
			}

			return federatedIdentity;

		} catch (IdentityBrokerException ex) {
			logger.error("Got response " + response);
			throw ex;
		}
	}

	protected class OIDCEndpoint extends Endpoint {

		private final ProSanteConnectIdentityProviderConfig config;

		public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
				ProSanteConnectIdentityProviderConfig config,
				AbstractOAuth2IdentityProvider<OIDCIdentityProviderConfig> provider) {
			super(callback, realm, event, provider);
			this.config = config;
		}

		@GET
		@Path("logout_response")
		public Response logoutResponse(@QueryParam("state") String state) {

			if (state == null && config.isIgnoreAbsentStateParameterLogout()) {
				logger.warn("using usersession from cookie");
				var authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, false);
				if (authResult == null) {
					return noValidUserSession();
				}

				var userSession = authResult.getSession();
				return AuthenticationManager.finishBrowserLogout(session, realm, userSession,
						session.getContext().getUri(), clientConnection, headers);
			} else if (state == null) {
				logger.error("no state parameter returned");
				sendUserSessionNotFoundEvent();

				return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
						Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
			}

			var userSession = session.sessions().getUserSession(realm, state);
			if (userSession == null) {
				return noValidUserSession();
			} else if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
				logger.error("usersession in different state");
				sendUserSessionNotFoundEvent();
				return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
			}

			return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(),
					clientConnection, headers);
		}

		private Response noValidUserSession() {
			logger.error("no valid user session");
			sendUserSessionNotFoundEvent();

			return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
					Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
		}

		private void sendUserSessionNotFoundEvent() {
			var event = new EventBuilder(realm, session, clientConnection);
			event.event(EventType.LOGOUT);
			event.error(Errors.USER_SESSION_NOT_FOUND);
		}
	}

	ProSanteConnectIdentityProvider(KeycloakSession session, ProSanteConnectIdentityProviderConfig config) {
		super(session, config);
		if (useJwks(config)) {
			this.jwks = Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session);
		}
	}

	private static boolean useJwks(ProSanteConnectIdentityProviderConfig config) {
		return config.isUseJwksUrl() && config.getJwksUrl() != null;
	}

	@Override
	protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
		var config = getConfig();
		var authenticationSession = request.getAuthenticationSession();

		authenticationSession.setClientNote(OAuth2Constants.ACR_VALUES, config.getEidasLevel().toString());
		var uriBuilder = super.createAuthorizationUrl(request);

		var nonce = DatatypeConverter.printHexBinary(Utils.generateRandomBytes(32));
		authenticationSession.setClientNote(BROKER_NONCE_PARAM, nonce);
		uriBuilder.replaceQueryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

		logger.debugv("PSC Authorization Url: {0}", uriBuilder.build().toString());

		return uriBuilder;
	}

	public String getIdTokenForLogout(UserSessionModel userSession) {
		var idToken = userSession.getNote(FEDERATED_ID_TOKEN);
		return isJWETokenFormatRequired(idToken) ? decryptJWE(idToken) : idToken;
	}

	@Override
	public JsonWebToken validateToken(String encodedToken) {
		var ignoreAudience = false;
		var token = isJWETokenFormatRequired(encodedToken) ? decryptJWE(encodedToken) : encodedToken;

		return validateToken(token, ignoreAudience);
	}

	@Override
	protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken,
			JsonWebToken idToken) throws IOException {
		var id = idToken.getSubject();
		var identity = new BrokeredIdentityContext(id);

		var name = (String) idToken.getOtherClaims().get(IDToken.NAME);
		var givenName = (String) idToken.getOtherClaims().get(IDToken.GIVEN_NAME);
		var familyName = (String) idToken.getOtherClaims().get(IDToken.FAMILY_NAME);
		var preferredUsername = (String) idToken.getOtherClaims().get(getusernameClaimNameForIdToken());
		var email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);

		var userInfoUrl = getUserInfoUrl();
		if (!getConfig().isDisableUserInfoService() && userInfoUrl != null && !userInfoUrl.isEmpty()
				&& accessToken != null) {
			var response = executeRequest(userInfoUrl,
					SimpleHttp.doGet(userInfoUrl, session).header("Authorization", "Bearer " + accessToken));
			var contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);

			MediaType contentMediaType;
			try {
				contentMediaType = MediaType.valueOf(contentType);
			} catch (IllegalArgumentException ex) {
				contentMediaType = null;
			}
			if (contentMediaType == null || contentMediaType.isWildcardSubtype() || contentMediaType.isWildcardType()) {
				throw new RuntimeException(
						"Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
			}

			JsonNode userInfo;

			if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentMediaType)) {
				userInfo = response.asJson();
			} else if (APPLICATION_JWT_TYPE.isCompatible(contentMediaType)) {
				try {
					var jwt = isJWETokenFormatRequired(response.asString()) ? decryptJWE(response.asString())
							: response.asString();

					userInfo = getJsonFromJWT(jwt);
				} catch (IdentityBrokerException ex) {
					throw new RuntimeException(
							"Failed to verify signature of userinfo response from [" + userInfoUrl + "].", ex);
				}
			} else {
				throw new RuntimeException(
						"Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
			}

			id = getJsonProperty(userInfo, "sub");
			name = getJsonProperty(userInfo, "name");
			givenName = getJsonProperty(userInfo, IDToken.GIVEN_NAME);
			familyName = getJsonProperty(userInfo, IDToken.FAMILY_NAME);
			preferredUsername = getUsernameFromUserInfo(userInfo);
			email = getJsonProperty(userInfo, "email");
			AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());
		}

		identity.setId(id);
		identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

		identity.setFirstName(givenName);
		identity.setLastName(familyName);

		if (givenName == null && familyName == null) {
			identity.setLastName(name);
		}

		identity.setEmail(email);
		identity.setBrokerUserId(getConfig().getAlias() + "." + id);

		var emailOptional = Optional.ofNullable(email);
		preferredUsername = Optional.ofNullable(preferredUsername).or(() -> emailOptional).orElse(id);
		identity.setUsername(preferredUsername);

		if (tokenResponse != null && tokenResponse.getSessionState() != null) {
			identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
		}

		if (tokenResponse != null) {
			identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
			processAccessTokenResponse(identity, tokenResponse);
		}

		return identity;
	}

	private boolean isJWETokenFormatRequired(String token) {
		String[] parts = token.split("\\.");
		return parts.length > 3;
	}

	private String decryptJWE(String encryptedJWE) {
		try {
			var jwe = new JWE(encryptedJWE);
			var kid = jwe.getHeader().getKeyId();

			// Finding the key from all the realms keys
			var key = session.keys().getKeysStream(session.getContext().getRealm())
					.filter(k -> k.getKid().equalsIgnoreCase(kid)).findFirst().map(KeyWrapper::getPrivateKey)
					.orElseThrow(() -> new IdentityBrokerException("No key found for kid " + kid));

			logger.debug("Found corresponding secret key for kid " + kid);
			jwe.getKeyStorage().setDecryptionKey(key);
			return new String(jwe.verifyAndDecodeJwe().getContent(), StandardCharsets.UTF_8);
		} catch (JWEException ex) {
			throw new IdentityBrokerException("Invalid token", ex);
		}
	}

	private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
		var response = request.asResponse();

		if (response.getStatus() != OK.getStatusCode()) {
			throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + response.asString());
		}
		return response;
	}

	private JsonNode getJsonFromJWT(String jwt) throws IdentityBrokerException {
		JWSInput jwsInput;

		try {
			jwsInput = new JWSInput(jwt);
		} catch (JWSInputException cause) {
			throw new IdentityBrokerException("Failed to parse JWT userinfo response", cause);
		}

		if (!verify(jwsInput)) {
			throw new IdentityBrokerException("Failed to verify signature of of jwt");
		}

		try {
			return JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
		} catch (IOException e) {
			throw new IdentityBrokerException("Failed to parse jwt", e);
		}
	}
}
