<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\facades\Hash;

class AuthController extends Controller
{
    public function register( Request $request ){
        $fields =$request->validate([
            'first_name'=>'required|string',
            'last_name'=>'required|string',
            'email'=>'required|string|unique:users,email',
            'password'=>'required|string|confirmed'
        ]);
        $full_name = $fields['first_name'] ." ".$fields['last_name'];

        $user = User::create([
            'name'=> $full_name,
            'email'=>$fields['email'],
            'password'=>bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }




    public function login( Request $request ){
        $fields =$request->validate([
            'email'=>'required|string',
            'password'=>'required|string'
        ]);


        //check email
        $user = user::where('email',$fields['email'])->first();

        //check password
        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message'=>'Bad creds'
            ], 401);
        }


        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }



    public function logout(Request $request) {
        auth()->user()->tokens()->delete();

        return[
            'message'=>'logged out'
        ];
    }
}
