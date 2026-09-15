import { NextFunction, Request, Response } from "express";
import { catchAsync } from "../utils/catchAsync";
import z, { ZodObject } from "zod";

export const validateRequest =(zodSchema: z.ZodObject) =>{
    return catchAsync((req:Request,res:Response,next:NextFunction)=>{

    const payload = req.body ?? {};

    const result = zodSchema.safeParse(payload)

        if(!result.success){
        let errorMessage = "";

        result.error.issues.forEach(issues =>{
            errorMessage = errorMessage.concat(issues.message,',')
        })
        throw new Error(errorMessage)
        
    };

    req.body = result.data 

    next();
})
}
