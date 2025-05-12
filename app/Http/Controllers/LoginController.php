<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    public function index()
    {
        return view('login');
    }

    public function auth(Request $req)
    {
        $credentials = $req->validate([
            'username' => 'required',
            'password' => 'required',
        ]);

        $remember = false;
        if ($req->has('remember') && $req->remember === 'on') {
            $remember = true;
        }

        // Membersihkan input
        $credentials['username'] = htmlspecialchars($credentials['username'], ENT_QUOTES, 'UTF-8');
        $credentials['password'] = htmlspecialchars($credentials['password'], ENT_QUOTES, 'UTF-8');

        // Cari user berdasarkan username
        $user = \App\Models\User::where('username', $credentials['username'])->first();

        // Verifikasi password menggunakan Hash::check
        if ($user && Hash::check($credentials['password'], $user->password)) {
            Auth::login($user, $remember); // Login user
            $req->session()->regenerate();
            $response['status'] = '1';
            $response['msg'] = 'Login berhasil';
            $response['url'] = url('dashboard');
        } else {
            $response['status'] = '0';
            $response['msg'] = 'Periksa username dan password';
        }

        return response()->json($response);
    }

    public function logout(Request $req)
    {
        Auth::logout();
        $req->session()->invalidate();
        $req->session()->regenerateToken();
        return redirect()->route('login');
    }
}
