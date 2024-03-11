<?php

namespace App\Http\Middleware;


use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\JWTAuth;

class ApiJwtAuth
{
    /**
     * @var \Tymon\JWTAuth\JWTAuth
     */
    protected $auth;
    /**
     * Create a new BaseMiddleware instance.
     *
     * @param \Tymon\JWTAuth\JWTAuth  $auth
     */
    public function __construct(JWTAuth $auth)
    {
        $this->auth = $auth;
    }
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (! $this->auth->parser()->setRequest($request)->hasToken()) {
            return $this->respond('token_not_provided', 422); //缺少令牌
        }
        try {
            if (!$user = $this->auth->parseToken()->authenticate()) {
                return $this->respond('user_not_found', 404);
            }
        } catch (TokenExpiredException $e) {
            return $this->respond('token_expired', 401); //令牌过期
        } catch (JWTException $e) {
            return $this->respond('token_invalid', 400); //令牌无效
        }

        return $next($request);
    }
    /**
     * Fire event and return the response.
     *
     * @param  string   $error
     * @param  int      $status
     * @return mixed
     */
    protected function respond($error, $status)
    {
        return response()->json(['error' => $error], $status);
    }
}