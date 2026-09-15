import z from "zod";

 const PatientRegistationZodSchema = z.object({
	name : z.string("Not a string!").min(3,"Name Must be 3 character long!"),
	email : z.email("Not Email!"),
	password : z.string() 
				.min(8,"Password must be at least 8 characters long" )
  				.max(20,"Password cannot exceed 20 characters")
  				.refine((val) => /[A-Z]/.test(val), "Password must contain at least one uppercase letter")
  				.refine((val) => /[a-z]/.test(val),"Password must contain at least one lowercase letter")
  				.refine((val) => /[0-9]/.test(val), "Password must contain at least one number")
  				.refine((val) => /[!@#$%^&*]/.test(val),"Password must contain at least one special character (!@#$%^&*)"),
	patient : z.object({
		contactNumber : z.string().optional()
	}).optional()
})

export const patientValidation ={
    PatientRegistationZodSchema
} 