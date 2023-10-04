<?php

namespace App\Util\Webfinger;

use App\Util\Lexer\Nickname;

class WebfingerUrl
{
    public static function generateWebfingerUrl($url)
    {
	    $handle = Nickname::normalizeProfileUrl($url);
	    \Log::debug('Normalised handle: ' . print_r($handle, true));
	    if (is_array($handle)) {
			// the url was a user handle
			$domain = $handle['domain'];
			$username = $handle['username'];
			$resource = "acct:{$username}@{$domain}";
	    } else {
		    // it could be an actual URL https://domain/endpoint
		    //
		    // (no idea why streams encodes the url here, parsing doesn't work any more if I leave this
		    //$resource = urlencode($url);
		    $resource = $url;
		    \Log::debug('Resource to check: ' . print_r($resource, true));

			if (str_starts_with($resource, 'http')) {
				$m = parse_url($resource);
				\Log::debug('Parsed: ' . print_r($m, true));
				if ($m) {
					if ($m['scheme'] !== 'https') {
						return false;
					}
					if (!array_key_exists('host', $m)) {
						return false;
					}
					$domain = $m['host'] . (array_key_exists('port', $m) ? ':' . $m['port'] : '');
				} else {
					return false;
				}
			}
		
	    }

	    $path = "https://{$domain}/.well-known/webfinger?resource={$resource}";
	    \Log::debug('WebfingerURL = ' . print_r($path, true));

        return $path;
    }
}
