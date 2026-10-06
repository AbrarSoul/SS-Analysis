import { Request, Response, NextFunction } from 'express';
import * as Services from './user.services'
import { userResponce } from '../../types/userResponse';
import { IUserInput, User } from './user.model';
import { catchAsync } from '../../utils/catchAsync';
import { AppError } from '../../utils/appError';
import { LoginType, EmailType, ResetPassword } from './user.schema';
import { Email } from '../../utils/email';
import crypto from 'crypto'
import { RefreshToken } from './refreshToken.model';
import { generateRefreshToken, signToken, verifyRefreshToken } from '../../utils/jwt'



export const signup = catchAsync(async (req: Request<{}, userResponce, IUserInput>, res: Response<userResponce>, next: NextFunction) => {
    const existUser = await Services.findUser(req.body.email)
    if (existUser) {
        throw new AppError('this email is already exists, choose another one.', 400)
    }
    const user = await Services.createOne({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm,
        passwordChangedAt: req.body.passwordChangedAt
    })
    const url = `${req.protocol}://${req.get('host')}/api/v1/users/me`
    await new Email(user, url).sendWelcome()

    Services.createRereshToken(user, res)
    Services.createSendToken(user, res, 201)

})

export const login = catchAsync(async (req: Request<{}, userResponce, LoginType>, res: Response<userResponce>, next: NextFunction) => {
    const { email, password } = req.body;

    const user = await Services.findUser(email);

    if (!user || !(await user.correctPassword(password, user.password))) {
        throw new AppError('Incorrect email or password', 401)
    }

    Services.createRereshToken(user, res)
    Services.createSendToken(user, res, 200)
})

export const refreshToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const oldRefreshToken = req.cookies.refreshToken;
    if (!oldRefreshToken) return next(new AppError('Please Log in to get the refresh token', 401));

    const payload = await verifyRefreshToken(oldRefreshToken); 

    const storedToken =  await RefreshToken.findOneAndDelete({ user: payload.id, token: oldRefreshToken })
    if (!storedToken) return next(new AppError('this token is not issued!!', 403));

    
    const user = await Services.getOneById(payload.id)
    if (!user) return next(new AppError('this user is not existed!!', 403));

    const newAccessToken = signToken({ id: payload.id });
    Services.createRereshToken(user, res)
    res.status(200).json({ accessToken: newAccessToken });

});

export const logout = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.refreshToken;
    if (token) {
        await RefreshToken.deleteOne({ token });
    }
    res.clearCookie('refreshToken', { path: '/api/v1/auth/refresh-token' });
    res.status(204).json({
        status: 'success',
        data: {

        }
    });
});


export const forgetPassword = catchAsync(async (req: Request<{}, userResponce, EmailType>, res: Response<userResponce>, next: NextFunction) => {
    // 1- get the user 
    const user = await Services.findUser(req.body.email)
    if (!user) {
        return next(new AppError('there is no user with this email address', 404))
    }
    // 2- generate a token
    const resetToken = user.createPasswordRestetToken()
    await user.save({ validateBeforeSave: false })




    // 3- send a link to the user's email

    try {
        const host = process.env.NODE_ENV === 'development' ? process.env.DEVELOPMENT_BASE_URL: process.env.PRODUCTION_BASE_URL
        const resetPasswordUrl = `${req.protocol}://${host}/api/v1/auth/resetPassword/${resetToken}`
        await new Email(user, resetPasswordUrl).sendPasswordReset()

        res.status(200).json({
            status: 'success',
            message: 'the link sent to your email'
        })

    }
    catch (err) {
        user.PasswordResetToken = undefined
        user.passwordResetExpires = undefined

        await user.save({ validateBeforeSave: false })

        return next(new AppError('there is an error sending the email', 500))

    }

})
export const resetPassword = catchAsync(async (req: Request<{ token: string }, userResponce, ResetPassword>, res: Response<userResponce>, next: NextFunction) => {
    //1- get the user based on the token
    const token = req.params.token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex')
    const user = await Services.findUserByToken(hashedToken)


    //2- if the user exists and the token is not expired , set the new password and update change password at
    if (!user) {
        return next(new AppError('Invalid Or Expired Token', 400))
    }
    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm
    user.PasswordResetToken = undefined
    user.passwordResetExpires = undefined
    await user.save()



    // 3- log he user in (send jwt)
    Services.createSendToken(user, res, 200)

})

export const updateMyPassword = catchAsync(async (req: Request, res: Response<userResponce>, next: NextFunction) => {
    // 1-  get the user
    const user = await Services.findUserWithPassById(req.user!._id.toString());
    if (!user) {
        throw new AppError('user not found', 404)
    }

    // 2- check if the password is correct 
    const isMatch = await user.correctPassword(req.body.currentPassword, user.password)
    if (!isMatch)
        return next(new AppError('Incorrect current password', 401));

    // 3- if correct , update the password 
    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm

    await user.save()
    // 4- log the user in (send jwt)
    Services.createSendToken(user, res, 200)
})
// export const signup = catchAsync(async (req: Request<{}, userResponce, IUser >, res: Response<userResponce>, next: NextFunction) => {
// })
