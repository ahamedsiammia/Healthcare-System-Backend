import bcrypt from "bcryptjs";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import {
	authProvider,
	Role,
	UserStatus,
} from "../../../generated/prisma/enums";
import config from "../../config";
import { prisma } from "../../lib/prisma";
import { jwtUtils } from "../../utils/jwt";
import type {
	IEmailVerification,
	IForgotPassword,
	IGoogleLoinPayload,
	ILoginUserPayload,
	IRegisterPatientPayload,
	IRequestUser,
	IResetPassword,
} from "./auth.interface";
import { googleClient } from "../../lib/googleAuth";
import { GoogleAuth, type TokenPayload } from "google-auth-library";
import { error } from "node:console";
import crypto from "crypto"
import { redisClient } from "../../lib/redis";
import { transporter } from "../../lib/nodemailer";


const registerPatient = async (payload: IRegisterPatientPayload) => {
	const { name, password, email, patient:patientData } = payload;
	const isUserExists = await prisma.user.findUnique({
		where: {
			email: email,
		},
	});

	if (isUserExists) {
		throw new Error("User with this email already exists");
	}

	const hashedPassword = await bcrypt.hash(password, 10);


	const otp = crypto.randomInt(111111,1000000)

	const key = `Register-otp-key:${email}`;
	
	await redisClient.set(key,otp,{
		expiration : {
			type : "EX",
			value : 5 * 60
		}
	});


 await transporter.sendMail({
  from: config.email_sender,
  to: email,
  subject: "HealthCare - Verify Your Email",
  html: `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Verify Your HealthCare Account</title>
      </head>

      <body style="
        margin: 0;
        padding: 0;
        background-color: #f4f7f9;
        font-family: Arial, Helvetica, sans-serif;
      ">

        <div style="
          width: 100%;
          padding: 45px 15px;
          box-sizing: border-box;
        ">

          <div style="
            max-width: 570px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 18px;
            overflow: hidden;
            box-shadow: 0 8px 35px rgba(15, 23, 42, 0.08);
          ">

            <!-- Header -->
            <div style="
              padding: 32px 25px;
              text-align: center;
              background: linear-gradient(135deg, #00bfa6, #009e87);
            ">

              <h1 style="
                margin: 0;
                color: #ffffff;
                font-size: 30px;
                font-weight: 700;
                letter-spacing: 0.5px;
              ">
                HealthCare
              </h1>

              <p style="
                margin: 8px 0 0;
                color: #d9fffa;
                font-size: 14px;
              ">
                Your Health, Our Priority
              </p>

            </div>


            <!-- Main Content -->
            <div style="
              padding: 42px 38px;
              text-align: center;
            ">

              <div style="
                width: 68px;
                height: 68px;
                margin: 0 auto 22px;
                border-radius: 50%;
                background-color: #e7f9f5;
                text-align: center;
                line-height: 68px;
                font-size: 30px;
              ">
                ✉
              </div>

              <h2 style="
                margin: 0 0 14px;
                color: #172033;
                font-size: 25px;
                font-weight: 700;
              ">
                Verify Your Email Address
              </h2>

              <p style="
                margin: 0 auto;
                max-width: 440px;
                color: #64748b;
                font-size: 15px;
                line-height: 1.7;
              ">
                Welcome to HealthCare! To complete your registration,
                please verify your email address using the verification
                code below.
              </p>


              <!-- OTP -->
              <div style="
                margin: 30px auto 20px;
                padding: 22px 20px;
                max-width: 300px;
                background-color: #f0fdfa;
                border: 1px solid #99f6e4;
                border-radius: 14px;
              ">

                <p style="
                  margin: 0 0 10px;
                  color: #64748b;
                  font-size: 12px;
                  font-weight: 600;
                  text-transform: uppercase;
                  letter-spacing: 1.5px;
                ">
                  Verification Code
                </p>

                <div style="
                  color: #009e87;
                  font-size: 36px;
                  font-weight: 700;
                  letter-spacing: 9px;
                ">
                  ${otp}
                </div>

              </div>


              <!-- Expiry -->
              <p style="
                margin: 0;
                color: #ef4444;
                font-size: 13px;
                font-weight: 600;
              ">
                This verification code will expire in 5 minutes.
              </p>


              <!-- Info Box -->
              <div style="
                margin: 28px auto 0;
                padding: 17px 18px;
                max-width: 410px;
                background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                text-align: left;
              ">

                <p style="
                  margin: 0;
                  color: #64748b;
                  font-size: 13px;
                  line-height: 1.7;
                ">
                  Enter this OTP on the HealthCare verification page
                  to activate your account. For your security, do not
                  share this code with anyone.
                </p>

              </div>


              <!-- Warning -->
              <p style="
                margin: 28px auto 0;
                max-width: 430px;
                color: #94a3b8;
                font-size: 12px;
                line-height: 1.7;
              ">
                If you did not create a HealthCare account, you can safely
                ignore this email. No account will be verified without
                this code.
              </p>

            </div>


            <!-- Footer -->
            <div style="
              padding: 24px 25px;
              text-align: center;
              background-color: #f8fafc;
              border-top: 1px solid #e5e7eb;
            ">

              <p style="
                margin: 0;
                color: #64748b;
                font-size: 12px;
                line-height: 1.7;
              ">
                This is an automated verification email from HealthCare.
                <br />
                Please do not reply to this email.
              </p>

              <p style="
                margin: 12px 0 0;
                color: #94a3b8;
                font-size: 12px;
              ">
                © ${new Date().getFullYear()} HealthCare. All rights reserved.
              </p>

            </div>

          </div>

        </div>

      </body>
    </html>
  `,
  });


	const createdUser = await prisma.user.create({
		data: {
			name,
			email,
			password: hashedPassword,
			role: Role.PATIENT,
			status: UserStatus.ACTIVE,
			emailVerified: false,
			patient: {
				create: { name, email , contactNumber :patientData?.contactNumber},
			},
		},
		omit: { password: true },
		include: { patient: true },
	});

	const { patient, ...user } = createdUser;
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret as string,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		user,
		patient,
		accessToken,
		refreshToken,
	};
};

const emailVerification = async (payload:IEmailVerification)=>{
	const {email,otp}=payload;

	const isUserExists = await prisma.user.findUnique({
		where : {
			email
		}
	});

	if(!isUserExists){
		throw new Error("User Dose Not Exist")
	};

	const key = `Register-otp-key:${email}`

	const redisOtp = await redisClient.get(key);


	if(!redisOtp){
		throw new Error("Invalid OTP")
	}

	if(redisOtp !== otp){
		throw new Error("Dose Not Match OTP")
	}

	await prisma.user.update({
		where : {
			email
		},
		data : {
			emailVerified : true
		}
	});

	await redisClient.del([key]);


}

const loginUser = async (payload: ILoginUserPayload) => {
	const { password } = payload;
	const email = payload.email.trim().toLowerCase();

	const user = await prisma.user.findUnique({
		where: { email },
	});

	if (!user) {
		throw new Error("User not found");
	}

	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}

	if (user.password === null && user.googleId !== null) {
		throw new Error(
			"User Already Has Account Register With Google.Try to Login with Google.",
		);
	}

	const isPasswordMatched = await bcrypt.compare(
		password,
		user.password as string,
	);

	if (!isPasswordMatched) {
		throw new Error("Invalid credentials");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const getMe = async (user: IRequestUser) => {
	const isUserExists = await prisma.user.findUnique({
		where: {
			id: user.userId,
		},
		include: {
			patient: true,
		},
		omit: {
			password: true,
		},
	});

	if (!isUserExists) {
		throw new Error("User not found");
	}

	return isUserExists;
};

const refreshToken = async (token: string) => {
	const verifiedRefreshToken = jwtUtils.verifyToken(
		token,
		config.jwt_refresh_secret,
	);

	if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
		throw new Error(
			config.node_env === "development"
				? verifiedRefreshToken.error
				: "Invalid refresh token",
		);
	}

	const data = verifiedRefreshToken.data as JwtPayload;

	const user = await prisma.user.findUnique({
		where: { id: data.userId },
	});

	if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
		throw new Error("User is inactive or not found");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const googleLoin = async (payload: IGoogleLoinPayload) => {
	let googleIdTokenPayload: TokenPayload | null | undefined = null;

	try {
		const ticket = await googleClient.verifyIdToken({
			idToken: payload.idToken,
			audience: config.google_client_id,
		});

		googleIdTokenPayload = ticket.getPayload();
	} catch (error) {
		console.log("Google Id Toke  Verification Filed", error);
		throw new Error("Invalid or Expired Google Id or Token");
	}

	if (!googleIdTokenPayload) {
		throw new Error("Invalid or Expired Google Id or Token");
	}

	const isPatientExitsWithGoogleAuth = await prisma.user.findUnique({
		where: {
			email: googleIdTokenPayload.email,
			role: Role.PATIENT,
			googleId: googleIdTokenPayload.sub,
		},
	});

	if (!googleIdTokenPayload.email) {
		throw new Error("Google Email Not Found");
	}
	if (!googleIdTokenPayload.name) {
		throw new Error("Google User Name Not Found");
	}

	let user = isPatientExitsWithGoogleAuth;

	if (!isPatientExitsWithGoogleAuth) {
		const isPatientExitsWithCredential = await prisma.user.findUnique({
			where: {
				email: googleIdTokenPayload.email,
				role: Role.PATIENT,
				authProvider: authProvider.CREDENTIAL,
			},
		});

		if (isPatientExitsWithCredential) {
			if (!isPatientExitsWithCredential.emailVerified) {
				throw new Error("Email Not Verified");
			}

			if (isPatientExitsWithCredential.status === UserStatus.BLOCKED) {
				throw new Error("User is BLOCKED");
			}

			if (
				isPatientExitsWithCredential.isDeleted ||
				isPatientExitsWithCredential.status === UserStatus.DELETED
			) {
				throw new Error("User is Deleted");
			}

			user = await prisma.user.update({
				where: {
					id: isPatientExitsWithCredential.id,
				},
				data: {
					googleId: googleIdTokenPayload.sub,
				},
			});
		} else {
			// google register
			user = await prisma.user.create({
				data: {
					name: googleIdTokenPayload.name,
					email: googleIdTokenPayload.email,
					role: Role.PATIENT,
					googleId: googleIdTokenPayload.sub,
					authProvider: authProvider.GOOGLE,
					emailVerified: true,
					patient: {
						create: {
							name: googleIdTokenPayload.name,
							email: googleIdTokenPayload.email,
						},
					},
				},
			});
		}
	}

	if (!user) {
		throw new Error("User Not Found");
	}

	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User is BLOCKED");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is Deleted");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const forgotPassword = async(payload : IForgotPassword)=>{
	const {email} = payload;

	const isUserExists = await prisma.user.findUnique({
		where : {
			email : email
		}
	});

	if(!isUserExists){
		throw new Error("User Dose not Exist!")
	};

	if(!isUserExists.emailVerified){
		throw new Error("User Not Verified")
	}

	if(isUserExists.status === "BLOCKED"){
		throw new Error("User is Blocked")
	};

	if(isUserExists.isDeleted === true || isUserExists.status === "DELETED"){
		throw new Error("User is Deleted")
	};

	if(isUserExists.googleId &&isUserExists.authProvider === "GOOGLE"){
		throw new Error("User Has Account With Google")
	}


	const otp = crypto.randomInt(100000,1000000)

	const key = `forgot-password-key : ${isUserExists.email}`;

	await redisClient.set(key,otp,{
		expiration : {
			type : "EX",
			value : 5*60
		}
	})

	// send a otp with user mail

	await transporter.sendMail({
		from : config.email_sender,
		to : isUserExists.email,
		subject : "Forgot Password",
		html: ` <!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8" /> <meta name="viewport" content="width=device-width, initial-scale=1.0" /> <title>HealthCare - Password Reset</title> </head> <body style=" margin: 0; padding: 0; background-color: #f4f7fb; font-family: Arial, Helvetica, sans-serif; "> <div style=" width: 100%; padding: 40px 15px; box-sizing: border-box; "> <div style=" max-width: 560px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 8px 30px rgba(0, 0, 0, 0.08); "> <!-- Header --> <div style=" background: linear-gradient(135deg, #00bfa6, #00a98f); padding: 30px 25px; text-align: center; "> <h1 style=" margin: 0; color: #ffffff; font-size: 30px; font-weight: 700; letter-spacing: 0.5px; "> HealthCare </h1> <p style=" margin: 8px 0 0; color: #e6fffa; font-size: 14px; "> Your Health, Our Priority </p> </div> <!-- Content --> <div style=" padding: 40px 35px; text-align: center; "> <h2 style=" margin: 0 0 15px; color: #1f2937; font-size: 24px; "> Reset Your Password </h2> <p style=" margin: 0 auto 25px; max-width: 440px; color: #6b7280; font-size: 15px; line-height: 1.7; "> We received a request to reset the password for your HealthCare account. Use the verification code below to continue. </p> <!-- OTP Box --> <div style=" margin: 25px auto; padding: 18px 20px; max-width: 260px; background-color: #f0fdfa; border: 1px solid #99f6e4; border-radius: 12px; "> <p style=" margin: 0 0 8px; color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; "> Your OTP Code </p> <div style=" color: #00a98f; font-size: 34px; font-weight: 700; letter-spacing: 8px; "> ${otp} </div> </div> <p style=" margin: 20px 0 0; color: #ef4444; font-size: 13px; font-weight: 600; "> This OTP will expire in 5 minutes. </p> <p style=" margin: 25px auto 0; max-width: 430px; color: #6b7280; font-size: 13px; line-height: 1.6; "> If you did not request a password reset, please ignore this email. Your account will remain secure. </p> </div> <!-- Footer --> <div style=" background-color: #f8fafc; padding: 22px 25px; text-align: center; border-top: 1px solid #e5e7eb; "> <p style=" margin: 0; color: #94a3b8; font-size: 12px; line-height: 1.6; "> This is an automated email from HealthCare. <br /> Please do not reply to this email. </p> <p style=" margin: 12px 0 0; color: #64748b; font-size: 12px; "> © ${new Date().getFullYear()} HealthCare. All rights reserved. </p> </div> </div> </div> </body> </html> `

	})

};

const resetPassword =async(payload : IResetPassword)=>{
		const {email,otp,newPassword} = payload;

	const isUserExists = await prisma.user.findUnique({
		where : {
			email : email
		}
	});

	if(!isUserExists){
		throw new Error("User Dose not Exist!")
	};

	if(!isUserExists.emailVerified){
		throw new Error("User Not Verified")
	}

	if(isUserExists.status === "BLOCKED"){
		throw new Error("User is Blocked")
	};

	if(isUserExists.isDeleted === true || isUserExists.status === "DELETED"){
		throw new Error("User is Deleted")
	};

	if(isUserExists.googleId &&isUserExists.authProvider === "GOOGLE"){
		throw new Error("User Has Account With Google")
	}

	const key = `forgot-password-key : ${isUserExists.email}`;

	const redisOtp =await redisClient.get(key);

	if(!redisOtp){
		throw new Error("Invalid OTP")
	};

	if(redisOtp !== otp){
		throw new Error("OTP DOSE NOT MATCH")
	};

	const hashedPassword = await bcrypt.hash(newPassword,10);

	const updateUser = await prisma.user.update({
		where : {
			email : isUserExists.email
		},
		data : {
			password : hashedPassword
		}
	});

	await redisClient.del([key])


 await transporter.sendMail({
  from: config.email_sender,
  to: isUserExists.email,
  subject: "HealthCare - Password Reset Successful",
  html: `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>HealthCare - Password Reset Successful</title>
      </head>

      <body style="
        margin: 0;
        padding: 0;
        background-color: #f4f7f9;
        font-family: Arial, Helvetica, sans-serif;
      ">

        <div style="
          width: 100%;
          padding: 45px 15px;
          box-sizing: border-box;
        ">

          <div style="
            max-width: 570px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 18px;
            overflow: hidden;
            box-shadow: 0 8px 35px rgba(15, 23, 42, 0.08);
          ">

            <!-- Header -->
            <div style="
              padding: 30px 25px;
              text-align: center;
              background: linear-gradient(135deg, #00bfa6, #009e87);
            ">

              <h1 style="
                margin: 0;
                color: #ffffff;
                font-size: 30px;
                font-weight: 700;
                letter-spacing: 0.5px;
              ">
                HealthCare
              </h1>

              <p style="
                margin: 8px 0 0;
                color: #d9fffa;
                font-size: 14px;
              ">
                Your Health, Our Priority
              </p>

            </div>


            <!-- Main Content -->
            <div style="
              padding: 42px 38px;
              text-align: center;
            ">

              <!-- Success Icon -->
              <div style="
                width: 68px;
                height: 68px;
                margin: 0 auto 22px;
                border-radius: 50%;
                background-color: #e7f9f5;
                text-align: center;
                line-height: 68px;
                font-size: 32px;
              ">
                ✓
              </div>


              <h2 style="
                margin: 0 0 14px;
                color: #172033;
                font-size: 25px;
                font-weight: 700;
              ">
                Password Reset Successful
              </h2>


              <p style="
                margin: 0 auto;
                max-width: 440px;
                color: #64748b;
                font-size: 15px;
                line-height: 1.7;
              ">
                Your HealthCare account password has been successfully
                updated. You can now use your new password to sign in
                to your account.
              </p>


              <!-- Status Card -->
              <div style="
                margin: 30px auto;
                padding: 20px;
                max-width: 400px;
                background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                text-align: left;
              ">

                <p style="
                  margin: 0 0 8px;
                  color: #94a3b8;
                  font-size: 12px;
                  text-transform: uppercase;
                  letter-spacing: 1px;
                  font-weight: 600;
                ">
                  Account Security
                </p>

                <p style="
                  margin: 0;
                  color: #334155;
                  font-size: 14px;
                  line-height: 1.6;
                ">
                  Your password was changed successfully. For your
                  security, please keep your new password private.
                </p>

              </div>


              <!-- Security Warning -->
              <div style="
                margin: 25px auto 0;
                padding: 16px 18px;
                max-width: 400px;
                background-color: #fff8eb;
                border-left: 4px solid #f59e0b;
                border-radius: 6px;
                text-align: left;
              ">

                <p style="
                  margin: 0;
                  color: #92400e;
                  font-size: 13px;
                  line-height: 1.6;
                ">
                  <strong>Didn't reset your password?</strong>
                  If you did not make this change, please contact
                  HealthCare support immediately and secure your account.
                </p>

              </div>

            </div>


            <!-- Footer -->
            <div style="
              padding: 24px 25px;
              text-align: center;
              background-color: #f8fafc;
              border-top: 1px solid #e5e7eb;
            ">

              <p style="
                margin: 0;
                color: #64748b;
                font-size: 12px;
                line-height: 1.7;
              ">
                This is an automated security notification from HealthCare.
                <br />
                Please do not reply to this email.
              </p>

              <p style="
                margin: 12px 0 0;
                color: #94a3b8;
                font-size: 12px;
              ">
                © ${new Date().getFullYear()} HealthCare. All rights reserved.
              </p>

            </div>

          </div>

        </div>

      </body>
    </html>
  `,
});



}

export const AuthService = {
	registerPatient,
	loginUser,
	getMe,
	refreshToken,
	googleLoin,
	forgotPassword,
	resetPassword,
	emailVerification
};
