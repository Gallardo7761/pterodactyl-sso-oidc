<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services\OidcClientService;
use RuntimeException;

class OidcRedirectController extends Controller
{
    use OidcSettingsProvider;

    public function __construct(private OidcClientService $client)
    {
    }

    public function index(Request $request): RedirectResponse
    {
        $settings = $this->oidcSettings();

        if ($settings['enabled'] !== '1') {
            throw new RuntimeException('SSO login is not enabled.');
        }

        $this->assertSecureContext();

        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        // PKCE (RFC 7636): hex is a valid (if unusual) code_verifier charset -
        // every character is in the spec's unreserved set - so this reuses
        // the same generation style as state/nonce instead of introducing a
        // separate base64url-random helper just for this.
        $codeVerifier = bin2hex(random_bytes(32));

        $request->session()->put('ssooidc.state', $state);
        $request->session()->put('ssooidc.nonce', $nonce);
        $request->session()->put('ssooidc.code_verifier', $codeVerifier);
        $intended = $request->query('redirect_to', '/');
        $intended = is_string($intended) ? $intended : '/';
        if (!str_starts_with($intended, '/') || str_starts_with($intended, '//')
            || str_contains($intended, '\\') || preg_match('/[\x00-\x1f\x7f]/', $intended)) {
            $intended = '/';
        }
        $request->session()->put('ssooidc.intended', $intended);

        // Optional UX nicety: if the caller already knows who's likely
        // logging in (e.g. a link built with ?login_hint=user@example.com),
        // forward it so the provider can pre-fill its login form. Nothing
        // in this extension's own UI supplies one today, but the plumbing
        // is here for callers/integrations that do.
        $loginHint = $request->query('login_hint');

        $redirectUri = $this->extensionUrl('/extensions/{identifier}/callback');
        $authorizationUrl = $this->client->buildAuthorizationUrl(
            $settings,
            $redirectUri,
            $state,
            $nonce,
            $codeVerifier,
            $loginHint ? (string) $loginHint : null
        );

        return redirect()->away($authorizationUrl);
    }
}
