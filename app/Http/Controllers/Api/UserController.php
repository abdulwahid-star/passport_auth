<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function register(Request $request) {
        $validateData = $request->validate([
            'name' => 'required',
            'email' => ['required', 'email'],
            'password' => ['required', 'min:8', 'confirmed'],
        ]);

        $user = User::create($validateData);
        $token = $user->createToken('auth_token')->accessToken;
        // echo "<pre>";
        // print_r($user);
        // echo "</pre>";
        return response()->json([
            'message' => 'Successfuly registered',
            'user' => $user,
            'token' => $token,
            'status' => 1,
        ]);
    }

    public function login(Request $request) {
        $validator = Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);
        if ($validator->fails()) {
            return response->json([
                'message' => 'Validation Failed',
                'error' => $validator->errors,
                'status' => 0,
            ], 400);
        } else {
            $validateData = $validator->validated();
            $user = User::where(['email' => $validateData['email']])->first();
        if($user && Hash::check($validateData['password'], $user->password)) {
            $token = $user->createToken('auth_token')->accessToken;
            return response()->json([
                'message' => 'Successfuly logged in',
                'user' => $user,
                'token' => $token,
                'status' => 1,
            ], 200);
        } else {
            return response()->json([
                'message' => 'Invalid email or password',
                'status' => 0,
            ], 401);
        }
        }        
    }
    
    public function getUser($id) {
        $user = User::find($id);

        if (is_null($user)) {
            return response()->json([
                'message' => 'User not Found',
                'status' => 0
            ], 400);
        } else {
            return response()->json([
                'message' => 'User Found',
                'user' => $user,
                'status' => 1
            ], 200);
        }
    }
}
