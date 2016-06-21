<?php
namespace KeenVantage\FacebookAuthentication\Service;

use Facebook\Authentication\AccessToken;
use Facebook\Exceptions\FacebookSDKException;
use Facebook\Facebook;
use Facebook\GraphNodes\GraphUser;
use TYPO3\Flow\Annotations as Flow;

/**
 * @Flow\Scope("singleton")
 */
class FacebookService
{

    /**
     * @Flow\Inject(setting="secret", package="KeenVantage.FacebookAuthentication")
     */
    protected $secret;

    /**
     * @Flow\Inject(setting="id", package="KeenVantage.FacebookAuthentication")
     */
    protected $id;

    /**
     * @Flow\Inject(setting="namespace", package="KeenVantage.FacebookAuthentication")
     */
    protected $namespace;

    /**
     * @Flow\Inject(setting="graphVersion", package="KeenVantage.FacebookAuthentication")
     */
    protected $graphVersion = 'v2.4';

    /**
     * @return Facebook
     */
    public function getFacebookInstance()
    {
        return new Facebook([
            'app_id' => $this->id,
            'app_secret' => $this->secret,
            'default_graph_version' => $this->graphVersion
        ]);
    }

    /**
     * @return string
     */
    public function getFacebookLoginUrl()
    {
        if (!session_id()) {
            session_start();
        }
        $facebook = $this->getFacebookInstance();
        $helper = $facebook->getRedirectLoginHelper();
        $permissions = ['email'];
        return $helper->getLoginUrl('/authentication/facebook/login/callback', $permissions);
    }

    /**
     * @param AccessToken $accessToken
     * @return GraphUser
     */
    public function getUserFromGraph(AccessToken $accessToken)
    {
        $facebook = $this->getFacebookInstance();
        $response = $facebook->get('/me?fields=email,first_name,last_name', $accessToken);
        return $response->getGraphUser();
    }

    /**
     * @return AccessToken|null
     * @throws FacebookSDKException
     */
    public function getAccessToken()
    {
        $fb = $this->getFacebookInstance();
        $helper = $fb->getRedirectLoginHelper();
        $accessToken = $helper->getAccessToken();

        $oAuth2Client = $fb->getOAuth2Client();
        $tokenMetadata = $oAuth2Client->debugToken($accessToken);
        $tokenMetadata->validateAppId($this->getId());
        $tokenMetadata->validateExpiration();

        if (!$accessToken->isLongLived()) {
            $accessToken = $oAuth2Client->getLongLivedAccessToken($accessToken);
        }
        return $accessToken;
    }

    /**
     * Returns the Secret
     *
     * @return mixed
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Returns the Id
     *
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Returns the Namespace
     *
     * @return mixed
     */
    public function getNamespace()
    {
        return $this->namespace;
    }

    /**
     * Returns the GraphVersion
     *
     * @return mixed
     */
    public function getGraphVersion()
    {
        return $this->graphVersion;
    }

}