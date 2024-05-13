/**
 * idQ Client
 * Copyright(c) 2017 inBay Technologies Inc.
 * MIT Licensed
 */

/**
 * Import Dependencies
 */
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.OAuth;

/**
 * IdqClient implements a basic client for the idQ TaaS Backend API
 * for explicit authentication flow.
 */
public class IdqClient { 
 
	// OAuth 2.0 Client Configuration
    private String clientId;
    private String clientSecret;	
	private String redirectUrl;
 
	// idQ TaaS Backend Configuration
	private String oauthBaseUrl;
	private String oauthAuthzUrl;
    private String oauthTokenUrl;
	private String oauthUserUrl;
 
    IdqClient() {
		this.clientId = null;
		this.clientSecret = null;
		this.redirectUrl = null;
		this.oauthBaseUrl = null;
		this.oauthAuthzUrl = null;
		this.oauthTokenUrl = null;
		this.oauthUserUrl = null;
	}
	
	// Initialize OAuth 2.0 Client Configuration
	public void initOauthClient(String clientId, String clientSecret, String redirectUrl) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.redirectUrl = redirectUrl;
	}
 
	// Initialize idQ TaaS Backend Configuration
	public void initOauthServer(String serverName, String serverPort, String authzEndpoint, 
		String tokenEndpoint, String userEndpoint) {
		this.oauthBaseUrl = serverName + ":" + serverPort;
		this.oauthAuthzUrl = this.oauthBaseUrl + authzEndpoint;
		this.oauthTokenUrl = this.oauthBaseUrl + tokenEndpoint;
		this.oauthUserUrl = this.oauthBaseUrl + userEndpoint;
	}

    /**
     * Build a link to an idQ Authentication URL
     * using the configured OAuth 2.0 client credentials
     * and a given state.
	 * @param oauthState
     * @param oauthScope
     * @return authzReqUrl
     * @throws OAuthSystemException
     */
    public String getAuthzUrl(String oauthState, String oauthScope) throws OAuthSystemException {
       OAuthClientRequest oauthRequest = OAuthClientRequest
       		.authorizationLocation(this.oauthAuthzUrl)
            .setClientId(this.clientId)
            .setRedirectURI(this.redirectUrl)
            .setState(oauthState)
            .setScope(oauthScope)
            .setResponseType(ResponseType.CODE.toString())
            .buildQueryMessage();
        String authzReqUrl = oauthRequest.getLocationUri();   
        return authzReqUrl;        
    }

    /**
     * Exchange an authorization code for an access token
     * using the configured OAuth 2.0 client credentials
     * and a given authorization_code.
 	 * @param authzCode 
     * @return accessToken
     * @throws OAuthSystemException
     */
    public String getToken(String authzCode) throws OAuthSystemException, OAuthProblemException {
	    OAuthClientRequest oauth2request = OAuthClientRequest
			.tokenLocation(oauthTokenUrl)
			.setClientId(clientId) 
			.setClientSecret(clientSecret)
			.setRedirectURI(redirectUrl)
			.setCode(authzCode)
			.setGrantType(GrantType.AUTHORIZATION_CODE)
			.buildBodyMessage();
    	
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthJSONAccessTokenResponse oAuthResponse = oAuthClient.accessToken(oauth2request, 
			OAuthJSONAccessTokenResponse.class);
        String accessToken = oAuthResponse.getAccessToken();
        return accessToken;
    }

    /**
     * Exchange an access token for an idQ user info
     * using the configured OAuth 2.0 client credentials
     * and a given access token.
     * @param accessToken
     * @return userInfo
     * @throws OAuthSystemException
     * @throws OAuthProblemException
     */
    public String getUserInfo(String accessToken) throws OAuthSystemException, OAuthProblemException {
		OAuthClientRequest bearerClientRequest = new OAuthBearerClientRequest(oauthUserUrl)
			.setAccessToken(accessToken)
			.buildQueryMessage();
		
		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthResourceResponse resourceResponse = oAuthClient.resource(bearerClientRequest, 
             OAuth.HttpMethod.GET, OAuthResourceResponse.class);     
		String userInfo = resourceResponse.getBody();
		return userInfo;
    }

}
