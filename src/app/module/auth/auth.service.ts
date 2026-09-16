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

	console.log(hashedPassword);

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

};

const resetPassword =async(payload : IResetPassword)=>{
		const {email,otp,newPassword} = payload;
console.log(payload);
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
return updateUser

}

export const AuthService = {
	registerPatient,
	loginUser,
	getMe,
	refreshToken,
	googleLoin,
	forgotPassword,
	resetPassword
};
