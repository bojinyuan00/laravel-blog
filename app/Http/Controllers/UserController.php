<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;


class UserController extends Controller
{
    public function login(Request $request)
    {
        // 验证规则，由于业务需求，这里我更改了一下登录的用户名，使用手机号码登录
        $rules = [
            'name' => ['required'],
            'password' => 'required|string|min:6|max:20',
        ];

        // 验证参数，如果验证失败，则会抛出 ValidationException 的异常
        $params = $this->validate($request, $rules);

        // 使用 Auth 登录用户，如果登录成功，则返回 201 的 code 和 token，如果登录失败则返回
        $token = JWTAuth::attempt($params);
        if ($token) {
            return $this->responseData(['access_token' => $token]);
        } else {
            $this->responseError('账号或密码错误');
        }

    }

    /*
     * user register
     * 用户注册接口
     * @author bjy
     */
    public function register(Request $request)
    {
        // 注册用户
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        // 获取token
        $token = JWTAuth::fromUser($user);
        if (!$token) {
            return response(['code' => 200, 'error' => 'Account or password error.'], 400);
        }

        return response()->json(['code' => 200, 'message' => 'success', 'data' => $user, 'token' => $token], 200)->header('Authorization', 'Bearer ' . $token);
    }

    public function getToken(Request $request)
    {
        $request->validate([
            'name' => 'required|min:1|max:255',
            'password' => 'required|min:6|max:255'
        ]);

        if (!$token = JWTAuth::attempt($request->all())) {
            return response(['error' => 'Account or password error.'], 400);
        }

        return response()->json(['code' => 200, 'message' => 'success', 'token' => $token])->header('Authorization', 'Bearer ' . $token);;
    }

    public function getMe(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();

        return response()->json(['code'=>200,'message' => 'success', 'data' => $user]);
    }

    /*
     * 根据token获取用户的信息
     */
    public function profile(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();

        return response()->json(['user' => $user]);
    }

    /**
     * Refresh a token.
     * 刷新token，如果开启黑名单，以前的token便会失效。
     * 值得注意的是用上面的getToken再获取一次Token并不算做刷新，两次获得的Token是并行的，即两个都可用。
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }

    /**
     * Set the authentication header.
     *
     * @param \Illuminate\Http\Response|\Illuminate\Http\JsonResponse $response
     * @param string|null $token
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function setAuthenticationHeader($token = null)
    {
        $token = $token ?: $this->auth->refresh();

        return response()->json(['success' => true], 200)->header('Authorization', 'Bearer ' . $token);//注意'Bearer '这里有一个空格 　　
    }
}