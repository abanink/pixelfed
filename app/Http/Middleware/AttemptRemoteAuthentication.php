<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use App\Profile;
use App\Services\FollowerService;

class AttemptRemoteAuthentication
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
	\Log::info('In handler for Remote Authentication Attempt');
	$zid = $request->query('zid');
	if (!isset($zid) || preg_match('/^.+@.+$/i', $zid) === false) {
		return $next($request);
	}
	// strip possible leading "@" to get typical user@domain handle
	if (strncmp($zid, '@', 1) !== 0) {
		$zid = '@' . $zid;
	}
	\Log::info('Remote user (zid) = ' . print_r($zid, true));

	// TODO split the path to take the first string before any additional slash, for now this is limited to https://pixelfedsite.org/<username> requests
	$user = $request->path();
	\Log::info('Trying to access account of user ' . print_r($user, true));
	// TODO test if user $user exists, otherwise continue

	\Log::info('Trying remote authentication for remote user ' . print_r($zid, true));
	
	// TODO the criterium to determine if a remote user has access to a local resource should allow hooks and should be located elsewhere, and called from here
	// Proof-of-concept criterium: try to find the zid as a follower of the targeted user
	$followerProfile = Profile::whereUsername($zid)->first();
	$userProfile = Profile::whereUsername($user)->first();
	if (is_null($followerProfile) || is_null($userProfile) || ($followerProfile->id === $userProfile->id)) {
		\Log::info('No record for users - aborting attempt for remote authentication');
		return $next($request);
	}
	if (!FollowerService::follows($followerProfile->id, $userProfile->id)) {
		\Log::info(print_r($zid, true) . ' is NOT a follower of ' . print_r($user, true) . ' => NOT attempting remote auth');
		return $next($request);
	}
	\Log::info(print_r($zid, true) . ' is a follower of ' . print_r($user, true) . ' => going to attempt remote auth!');

	$fullUrl = $request->fullUrlWithoutQuery(['zid']);
	\Log::debug('Full url = ' . $fullUrl);
	$remoteDest = $fullUrl;
	if (strstr($remoteDest, '/magic')) {
		\Log::info('Destination already contains the /magic endpoint - avoiding recursion - not going to attempt remote auth');
		return $next($request);
	}
	\Log::info('dest = ' . print_r($remoteDest, true));
	$domain = substr(strrchr($zid, '@'), 1);
	$remoteUrl = 'https://' . $domain . '/magic' . '?f=&rev=1&owa=1&bdest=' . bin2hex($remoteDest);
	\Log::info('Remote url = ' . print_r($remoteUrl, true));

	return redirect()->away($remoteUrl);
    }
}
