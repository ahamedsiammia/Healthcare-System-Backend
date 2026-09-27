import { Request, Response } from "express";
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";
import httpStatus from "http-status";
import { userService } from "./user.service";

const uploadProfileImage = catchAsync(async(req:Request,res:Response)=>{
    console.log(req.file);

	const userId = req.user?.userId

	const result = await userService.uploadProfileImage(req.file?.buffer as Buffer,userId as string)
	sendResponse(res, {
		statusCode: httpStatus.OK,
		success: true,
		message: "Profile Image Upload successfully",
		data: result
	});
});


export const userController = {
    uploadProfileImage
}