<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;

use App\Profile;
use App\User;

class ValidateRemoteAuthentication
{

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        \Log::info('In handler for Remote Authentication Validation based on token');
	$owt = $request->query('owt');
        if (!isset($owt)) {
                return $next($request);
	}

	\Log::debug('owt token provided');

	// purge tokens older than 3 minutes
	self::purge(3);

	// find out which user to log in based on owt token
	$r = DB::table('owa_verifications')->where('token', $owt)->get();

	if ($r->isEmpty()) {
		\Log::info('Token not found');
		return redirect()->to($request->fullUrlWithoutQuery('owt'));
	}
	\Log::debug('Found this as token in our DB: ' . print_r($r, true));

	// TODO shouldn't we remove the token here as it has been consumed?
	
	$remote_profile = $r[0]->remote_url;	
	\Log::debug('Logging in as ' . $remote_profile);
	// TODO authenticate user based on 'profile'-based guard: if the user exists as a 'profile' we authenticate the user to log in

	$p = Profile::where('remote_url', $remote_profile)->first();
	if (!$p) {
		\Log::info('Failed to locate the profile in DB');
		return redirect()->to($request->fullUrlWithoutQuery('owt'));
	}

	$username = $p->username;
	\Log::info('Trying to log in username ' . $username);

	$user = User::whereUsername($username)->first();
	if (!$user) {
		\Log::info('User not found as a visitor - adding now');
		$user = User::create([ 
			'username' => $username,
			'name' => $p->name,
		]);
		$user->register_source = 'owa';
		$user->profile_id = $p->id;
		$user->save();
	} else {
		\Log::info('User found as a visitor');
	}

	\Log::info('Logging user <' . $user->name . '> in now');
	Auth::login($user);
	\Log::info('user logged in');

	// avoid session fixation attack by regenerating a new session ID
	$request->session()->regenerate();
	// remember the remotely authenticated visitor as authorized in this session 
	// TODO this should not be needed any more
//	$request->session()->put('authorized_profile', $p->id);

	// TODO test if we can just do 'return $next($request);'
	//	return redirect()->to($request->fullUrlWithoutQuery('owt'));
	return $next($request);
    }

    private function purge($minutes) {
	    $purged = DB::table('owa_verifications')->where('created_at', '<', now()->subMinutes($minutes)->toDateTimeString())->delete();
	    \Log::debug('Purged ' . print_r($purged, true) . ' token(s)');
    }
}
