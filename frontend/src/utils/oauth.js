/**
 * Generate a cryptographically random state string for CSRF protection.
 */
export function generateState() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Kick off an OAuth flow by:
 *  1. Generating and storing a state token in sessionStorage
 *  2. Redirecting to the backend initiation endpoint
 */
export function initiateOAuth(provider) {
  const state = generateState();
  sessionStorage.setItem("oauth_state", state);
  // Backend will use the state param and redirect to the provider
  window.location.href = `/api/auth/${provider}?state=${state}`;
}

/**
 * Validate the state returned from the OAuth callback.
 */
export function validateState(returnedState) {
  const stored = sessionStorage.getItem("oauth_state");
  sessionStorage.removeItem("oauth_state");
  return stored && stored === returnedState;
}
