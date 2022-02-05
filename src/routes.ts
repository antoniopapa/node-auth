import {Router} from "express";
import {AuthenticatedUser, GoogleAuth, Login, Logout, Refresh, Register, TwoFactor} from "./controller/auth.controller";
import {ForgotPassword, ResetPassword} from "./controller/forgot.controller";


export const routes = (router: Router) => {
    router.post('/api/register', Register);
    router.post('/api/login', Login);
    router.post('/api/two-factor', TwoFactor);
    router.get('/api/user', AuthenticatedUser);
    router.post('/api/refresh', Refresh);
    router.post('/api/logout', Logout);
    router.post('/api/google-auth', GoogleAuth);
    router.post('/api/forgot', ForgotPassword);
    router.post('/api/reset', ResetPassword);
}
