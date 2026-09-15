import bcrypt from "bcryptjs";
import { Role } from "../../generated/prisma/enums"
import { prisma } from "../lib/prisma"
import config from "../config";

export const seedSuperAdmin =async ()=>{
    try {
        const isSuperAdminExist = await prisma.user.findFirst({
            where : {
                role : Role.SUPER_ADMIN
            }
        });

        if(isSuperAdminExist){
            console.log("Super Admin Already Exist.");
            return;
        };

        const name  = config.super_admin_name as string
        const email =  config.super_admin_email as string
        const password = config.super_admin_password as string

        if(!name || !email || !password){
            throw new Error("Super Admin Name,Email,Password messing")
        }

        const hashPassword =await bcrypt.hash(password,10);

        const superAdmin = await prisma.user.create({
            data : {
                name  ,
                email,
                password : hashPassword,
                role : Role.SUPER_ADMIN,
                needPasswordChange : false,
                emailVerified : true
            }
        });

        console.log("Super Admin",superAdmin)

    } catch (error) {
        console.log("Error of Super Admin",error);

        await prisma.user.delete({
            where : {
                email : config.super_admin_email as string
            }
        })
    }
}

export const seedTesterAdmin =async ()=>{
    try {
        const isSuperAdminExist = await prisma.user.findUnique({
            where : {
                email : config.tester_admin_email
            }
        });

        if(isSuperAdminExist){
            console.log("tester Admin Already Exist.");
            return;
        };

        const name  = config.tester_admin_name as string
        const email =  config.tester_admin_email as string
        const password = config.tester_admin_password as string

        if(!name || !email || !password){
            throw new Error("Tester Admin Name,Email,Password messing")
        }

        const hashPassword =await bcrypt.hash(password,10);

        const superAdmin = await prisma.user.create({
            data : {
                name  ,
                email,
                password : hashPassword,
                role : Role.ADMIN,
                needPasswordChange : false,
                emailVerified : true
            }
        });

        console.log("Tester Admin",superAdmin)

    } catch (error) {
        console.log("Error of Super Admin",error);

        await prisma.user.delete({
            where : {
                email : config.tester_admin_email as string
            }
        })
    }
}

export const seedTesterDoctor =async ()=>{
    try {
        const isSuperAdminExist = await prisma.user.findUnique({
            where : {
                email : config.tester_doctor_email
            }
        });

        if(isSuperAdminExist){
            console.log("Tester Doctor Already Exist.");
            return;
        };

        const name  = config.tester_doctor_name as string
        const email =  config.tester_doctor_email as string
        const password = config.tester_doctor_password as string

        if(!name || !email || !password){
            throw new Error("Tester Doctor Name,Email,Password messing")
        }

        const hashPassword =await bcrypt.hash(password,10);

        const superAdmin = await prisma.user.create({
            data : {
                name  ,
                email,
                password : hashPassword,
                role : Role.DOCTOR,
                needPasswordChange : false,
                emailVerified : true
            }
        });

        console.log("Tester Doctor",superAdmin)

    } catch (error) {
        console.log("Error of Tester Doctor",error);

        await prisma.user.delete({
            where : {
                email : config.tester_doctor_email as string
            }
        })
    }
}