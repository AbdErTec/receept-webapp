<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class UserController extends Controller
{

    public function show($id) {
        //
        $targetUser = User::where('id', $id)->first();
        
        if(!$targetUser) {
            return response()->json([
                'error'=>'user not found'
            ], 404);
        }
    
        $this->authorize('view', $targetUser);

        return response()->json([
                'user' => [
                    'id' => (string) $targetUser->_id,
                    'email' => $targetUser->email,
                    'first_name' => $targetUser->first_name,
                    'last_name' => $targetUser->last_name,
                ]], 201);        
    }
    

    public function update(Request $request, $id) {
  
        $targetUser = User::where('id', $id)->first();
        
        if(!$targetUser) {
            return response()->json([
                'error'=>'user not found'
            ], 404);
        }
    
        $this->authorize('update', $targetUser);
        
        try{
       
            $targetUser -> update([
                'first_name' => $request->first_name,
                'last_name' => $request->last_name,
                'email' => $request->email,
                'phone_number' => $request->phone_number,
                'password' => Hash::make($request->password),
            ]);

            return response()->json([
                'message' => 'User updated', 
                'user' => [
                    'id' => (string) $targetUser->_id,
                    'email' => $targetUser->email,
                    'first_name' => $targetUser->first_name,
                    'last_name' => $targetUser->last_name,
                ]], 201);
        }
        catch (\Exception $e){
            Log::error('something went wrong when updating the profile', ['trace'=> $e->getTraceAsString()]);
                        return response()->json([
                'error'=>'Couldn t update the profile'
            ], (500));

        }
    }

    public function destroy (Request $request, $id) {
        //    
        $targetUser = User::where('id', $id)->first();
        
        if(!$targetUser) {
            return response()->json([
                'error'=>'user not found'
            ], 404);
        }
        $this->authorize('delete', $targetUser);

        try{
       
            $targetUser -> delete();

            return response()->json([
                'message' => 'User deleted', 
            ], 201);
        }
        catch (\Exception $e){
            Log::error('something went wrong when deleting the account', ['trace'=> $e->getTraceAsString()]);
                        return response()->json([
                'error'=>'Couldn t delete the account'
            ], (500));

        }

    }
    
}
