import { UploadApiResponse } from "cloudinary";
import cloudinary from "../../lib/cloudinary";
import { prisma } from "../../lib/prisma";

const uploadProfileImage = async (buffer: Buffer, userId: string) => {

  const currentUser = await prisma.user.findUnique({
    where : {
      id : userId
    },
    select : {
      imagePublicId : true,
      imageUrl : true
    }
  });

  const result = await new Promise<UploadApiResponse>((resolve, reject) => {
    cloudinary.uploader
      .upload_stream(
        {
          resource_type: "auto",
        },
        (error, result) => {
          if (error) {
            reject(error);
          } else {
            if(!result){
              throw new Error("Result not found")
            }
            resolve(result);
          }
        },
      )
      .end(buffer);
  });

  // Cloudinary upload শেষ হওয়ার পরে এখানে আসবে
  const updatedUser = await prisma.user.update({
    where: {
      id: userId,
    },
    data: {
      imageUrl: result.secure_url,
      imagePublicId: result.public_id,
    },
    omit: {
      password: true,
    },
  });

  if(currentUser?.imagePublicId && currentUser.imageUrl){
   await cloudinary.uploader.destroy(currentUser.imagePublicId,{
      invalidate : true
    })
  }

  return updatedUser;
};

export const userService = {
  uploadProfileImage,
};