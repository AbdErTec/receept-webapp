<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use App\Models\BlacklistedJWT;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;

class AuthController extends Controller
{
    public function login (Request $request) {
    // dd("in the login method");
    $request->validate([
        'email'=> 'required | string',
        'password'=> 'required | string',
    ]);
    $user = User::where('email', $request->email)->first();

    if (!$user|| !Hash::check($request->password, $user->password)) {

        return response()->json([
            'Error' => 'invalid credentials'
            ], 401
            );
        }
    $now = time();

    $accessPayload =[
        'sub'=> (string)$user->_id,
        'iat'=> $now,
        'exp'=> $now + 60 * 15, 
    ];

    $refreshPayload =[
        'sub'=> (string)$user->_id,
        'iat'=> $now,
        'exp'=> $now + 3600 * 24 * 7,
    ];

    $accessToken = JWT::encode($accessPayload, env('JWT_SECRET'), 'HS256');
    $refreshToken = JWT::encode($refreshPayload, env('JWT_SECRET'), 'HS256');

    return response()->json([
        'message' => 'connected successfuly',
        // 'token' => $jwt,
        'user' => [
            'id' => (string) $user->_id,
            'email' => $user->email,
            'first_name' => $user->first_name,
            'last_name' => $user->last_name,
        ]
    ], 201)
    ->cookie('accessToken',$accessToken, 15, '/', null, false, true)
    ->cookie('refreshToken',$refreshToken, 10080, '/', null, false, true); //to change in prod    
    }

    public function register (Request $request) {
    $request->validate([
        'first_name' => 'required | string',
        'last_name' => 'required | string',
        'email'=> 'required | string',
        'phone_number' => 'required | string', 
        'password'=> 'required | string | min:6',
    ]);
 
    $user = User::where('email', $request->email)->first();

    if ($user) {
        return response()->json([
            'Error' => 'User already exists'
            ], 401
            );
        }

    $newUser = User::create([
        'first_name' => $request->first_name,
        'last_name' => $request->last_name,
        'email' => $request->email,
        'phone_number' => $request->phone_number,
        'password' => Hash::make($request->password),
    ]);

    return response()->json([
        'message' => 'User created', 
        'user' => [
            'id' => (string) $newUser->_id,
            'email' => $newUser->email,
            'first_name' => $newUser->first_name,
            'last_name' => $newUser->last_name,
        ]], 201);
    }


    public function logout (Request $request) {
        // $header = $request->header('Authorization');
        $refreshToken = $request->cookie('refreshToken');
        // $token = str_replace('Bearer ', '', $header);
        // $token = trim($token);
        $payload = JWT::decode($refreshToken, new key (env('JWT_SECRET'), 'HS256'));
        $exp = $payload->exp;
        
        
        
       
        try { 
            Redis::setex("blacklist:$refreshToken", $exp - time(), 'blacklisted');
                }
        catch (\Exception $e) {

            log::error('Couldnt blacklist token', ['trace'=> $e->getTraceAsString()]);
            return response()->json([
                            'Error' => 'Couldnt blacklist the token', 
                        ], 500);
        
                        }            
        // }
         
        return response()->json([
                'message' => 'token is now blacklisted and cookies are erased', 
            ], 200)
             ->cookie('accessToken', '', -1)
            ->cookie('refreshToken', '', -1);
    }

    public function refresh(Request $request) {
    try {
        // Get refresh token from cookie
        $refreshToken = $request->cookie('refreshToken');
        
        if (!$refreshToken) {
            return response()->json(['error' => 'No refresh token'], 401);
        }
        
        // Decode refresh token
        $payload = JWT::decode($refreshToken, new Key(env('JWT_SECRET'), 'HS256'));
        
        // Check if expired
        if (time() > $payload->exp) {
            return response()->json(['error' => 'Refresh token expired'], 401);
        }
        
        // Check if blacklisted
        $isBlacklisted = Redis::get("blacklist:$refreshToken");
        if ($isBlacklisted) {
            return response()->json(['error' => 'Token revoked'], 401);
        }
        
        // Create new access token
        $now = time();
        $accessPayload = [
            'sub' => $payload->sub,
            'iat' => $now,
            'exp' => $now + 60 * 15,
        ];
        
        $newAccessToken = JWT::encode($accessPayload, env('JWT_SECRET'), 'HS256');
        
        // Return new access token as cookie
        return response()->json(['message' => 'Token refreshed'], 200)
            ->cookie('accessToken', $newAccessToken, 15, '/', null, false, true);
            
    } catch (\Exception $e) {
        Log::error('Refresh token error', ['error' => $e->getMessage()]);
        return response()->json(['error' => 'Invalid token'], 401);
    }
}

}
