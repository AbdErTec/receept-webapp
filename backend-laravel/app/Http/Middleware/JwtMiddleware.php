<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\BlacklistedJWT;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Auth;


class JwtMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
        // $header = $request->headers->all();
            // $header = $request->header('Authorization');
            // dd($request)
            $accessToken = $request->cookie('accessToken');
            if (!$accessToken) {
                
              return response()->json([
                    'error' => ['Session expired'],
                ], 401);

            }
            
            $payload = JWT::decode($accessToken, new key (env('JWT_SECRET'), 'HS256'));
            $user = User::find($payload->sub); // assuming sub = user_id
            $exp = $payload->exp;
            
            //decode the user id form the token

            if (!$user || (time()  > $exp)) {
                
              return response()->json([
                    'error' => ['Session expired'],
                ], 401);

            }

            $request->setUserResolver(fn() => $user);
            
            Auth::setUser($user);


            return $next($request);
        }
        catch (\Exception $e) {
            Log::error('An excpected error occured ' ,['trace'=> $e->getTraceAsString()]);
            return response()->json([
                'error' =>'Seesion denied',
            ], 403);
        }
    }
}
