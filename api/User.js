const express = require("express");
const router = express.Router();

//mongodb url model
const User = require("./../models/User");

//mongodb user verification model
const UserVerification = require("./../models/UserVerification");

//mongodb user verification model
const PasswordReset = require("./../models/PasswordReset");


//email handler
const nodemailer = require("nodemailer");

//unique string
const { v4: uuidv4 } = require("uuid");

//env variables
require("dotenv").config();

//password handler
const bcrypt = require("bcrypt");

//path for static verified page
const path = require("path");
// const { rmSync } = require("fs");

//nodemailer stuff
let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  }
})

//testing success
transporter.verify((error, success) => {
  if (error) {
    console.log(error)
  } else {
    console.log("Ready for message");
    console.log(success);
  }
})
// Signup
router.post("/signup", (req, res) => {
  console.log("signup")
  
  let { name, email, password, dateOfBirth } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();

  if (name == "" || email == "" || password == "" || dateOfBirth == "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields!",
    });
  } else if (!/^[a-zA-Z\s]*$/.test(name)) {
    res.json({
      status: "FAILED",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else if (!new Date(dateOfBirth).getTime()) {
    res.json({
      status: "FAILED",
      message: "Invalid date of birth entered",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "Password is too short!",
    });
  } else {
    // Checking if user already exists
    User.find({ email }).then((result) => {
      if (result.length) {
        res.json({
          status: "FAILED",
          message: "User with the provided email already exists",
        });
      } else {
        // Try to create a new user

        // Password handling
        const saltRounds = 10;
        bcrypt
          .hash(password, saltRounds)
          .then((hashedPassword) => {
            const newUser = new User({
              name,
              email,
              password: hashedPassword,
              dateOfBirth,
              verified: false,
            });

            newUser
              .save()
              .then((result) => {
                //handle account verification
                sendVerificationEmail(result, res);
              })
              .catch((err) => {
                res.json({
                  status: "FAILED",
                  message: "An error occurred while saving user account!",
                });
              });
          })
          .catch((err) => {
            res.json({
              status: "FAILED",
              message: "An error occurred while hashing password!",
            });
          });
      }
    }).catch((err) => {
      console.log(err);
      res.json({
        status: "FAILED",
        message: "An error occurred while checking for an existing user!",
      });
    });
  }
});

//send verification email
const sendVerificationEmail = ({ _id, email }, res) => {
console.log("verification mail sent")
//url to be used in the email

  const currentUrl = "http://localhost:5000/";

  const uniqueString = uuidv4() + _id;

  //mail options
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your Email",
    html: `<p>Verify your email address to complete the Signup process and then Login into your account.</p><p>This link <b>expires in 6 hours</b>.</p> <p> Press <a href=${currentUrl + "user/verify/" + _id + "/" + uniqueString}> here</a> to proceed. </p>`,
  }

  //hash the uniqueString
  const saltRounds = 10;
  bcrypt
  .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {

      //set values in userVerification collection

      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              //email sent and verification record saved!
              res.json({
                status: "PENDING",
                message: "verification email sent",
              })
            })
            .catch((error) => {
              console.log(error)
              res.json({
                status: "FAILED",
                message: "Verification email failed"
              })
            })
        }).catch((error) => {
          res.json({
            status: "FAILED",
            message: "Couldn't save verification email data!",
          })
        })
    })

    .catch(() => {
      res.json({
        status: "FAILED",
        message: "An error occurred while hashing email data!"
      })
    })
}

//verify email
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //user verification record exists so we proceed
        const { expiresAt } = result[0]
        const hashedUniqueString = result[0].uniqueString;
        //checking for expired unique string
        if (expiresAt < Date.now()) {
          //record has expired so we delete it
          UserVerification
            .deleteOne({ userId })
            .then(result => {
              User.deleteOne({ _id:userId })
                .then(() => {
                  let message = "Link has expired. Please sign up again";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                }).catch(error => {
                  let message = "clearing user with expired unique string faild";
                  res.redirect(`/user/verified/error=true&message=${message}`)
                })
            })
            .catch((error) => {
              console.log(error);
              let message = "An error occurred while clearing expired user verification record";
              res.redirect(`/user/verified/error=true&message=${message}`)
            })
        } else {
          //valid record exists so we validate the user string
          //First compare the hashed unique string

          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then(result => {
              if (result) {
                //strings match

                User
                  .updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification
                      .deleteOne({ userId })
                      .then(() => {
                        res.sendFile(path.join(__dirname, "./../views/verified.html"));
                      })
                      .catch(error => {
                        console.log(error)
                        let message = "An error occured while finalizing successful verification";
                        res.redirect(`/user/verified/error=true&message=${message}`);
                      })
                  })
                  .catch(error => {
                    console.log(error);
                    let message = "An error occurred while updating user record to show verified";
                    res.redirect(`/user/verified/error=true&message=${message}`)
                  })
              } else {
                //exsting record but incorrect verification details passed.
                let message = "Invalid verification details passed. Checked your inbox.";
                res.redirect(`/user/verified/error=true&message=${message}`)
              }
            }).catch(error => {
              let message = "An error occurred while comparing unique strings";
              res.redirect(`/user/verified/error=true&message=${message}`);
            })
        }
      } else {
        //user verification record doesn't exist
        let message = "Account record doesn't exist or has been verified already. Please sign up or log in.";
        res.redirect(`/user/verified/error=true&message=${message}`)
      }
    })
    .catch((error) => {
      console.log(error)
      let message = "An error occurred while checking for existing user verification record";
      res.redirect(`/user/verified/error=true&message=${message}`)
    })
})

// verified page route
router.get("/verified", (req, res) => {
  console.log("verified")
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
})

// Signin
router.post("/signin", (req, res) => {
  // Add your signin logic here

  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "Empty credentials supplied"
    })
  } else {
    User.find({ email })
      .then(data => {
        if (data.length) {
          //user exists

          //check if user is verified

          if (!data[0].verified) {
            res.json({
              status: "FAILED",
              message: "Email hasn't been verified yet. Check your inbox"
            })
          }
          else {
            const hashedPassword = data[0].password;
            bcrypt.compare(password, hashedPassword)
              .then(result => {
                if (result) {
                  //password match
                  res.json({
                    status: "SUCCESS",
                    message: "Signin successful",
                    data: data
                  })
                } else {
                  res.json({
                    status: "FAILED",
                    message: "Invalid password enterd!"
                  })
                }
              }).catch(err => {
                res.json({
                  status: "FAILED",
                  message: "An error occurred while comparing passwords"
                });
              });
          }


        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered!"
          })
        }
      })
      .catch(err => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user"
        })
      })
  }
});

// //actually reset the password

// router.post("/resetPassword",(req,res)=>{
//   let {userId,resetString,newPassword}=req.body;

//   PasswordReset.find({userId})
//   .then(result=>{
//     if(result.length>0){}
//     else{}

//   })
//   .catch(error=>{

//   })
// })

//password reset stuff
router.post("/requestPasswordReset",(req,res)=>{
  const {email,redirectUrl}=req.body;

  //check if email exists

  User.find({email})
  .then((data)=>{
    if(data.length){
      //user exists

      //check if user is verified

      if(!data[0].verified){
        res.json({
          status:"FAILED",
          message:"Email hasn't been verified yet. check your inbox",
        })
      }
      else{
        //proceed with email to reset password
        sendResetEmail(data[0],redirectUrl,res);
      }

    }
    else{
      res.json({
        status:"FAILED",
        message:"No account with the supplied email exists!"
      })
    }
  })
  .catch(error=>{
    console.log(error)
    res.json({
      status:"FAILED",
      message:"An error occurred while checking the existing user"
    })
  })
})

//send password reset email

const sendResetEmail=({_id,email},redirectUrl,res)=>{
const resetString=uuidv4()+_id;

//first, we clear all exsisting rest reset records 

PasswordReset
.deleteMany({userId:_id})
.then(result=>{
  //Reset records delete successfully
  //Now we send the email

  //mail options
const mailOptions = {
  from: process.env.AUTH_EMAIL,
  to: email,
  subject: "Password Reset",
  html: `<p>now you can reset your password</p><p>This link <b>expires in 1 hours</b>.</p> <p> Press <a href=${
    redirectUrl +"/" + _id + "/" + resetString}> here</a> to proceed. </p>`,
};
//hash the reset string

const saltRounds=10;
bcrypt
.hash(resetString,saltRounds)
.then(hashedResetString=>{

  //set values in password reset collection

  const newPasswordReset=new PasswordReset({
    userId:_id,
    resetString:hashedResetString,
    createdAt:Date.now(),
    expriesAt:Date.now()+3600000

  })
  newPasswordReset
  .save()
  .then(()=>{
    transporter
    .sendMail(mailOptions)
    .then(()=>{
      //reset email sent and password reset record saved
      res.json({
        status:"PENDING",
        message:"Password reset email sent"
      })
    
    }).catch(error=>{
      console.log(error);
      res.json({
        status:"FAILED",
        message:"Password reset email failed",
      })
    })
  })
  .catch(error=>{
    console.log(error)
    res.json({
      status:"FAILED",
      message:"Counldn't save password reset data!",
    })
  })
})
.catch(error=>{
  console.log(error)
  res.json({
    status:"FAILED",
    message:"An error occurred while hashing the password reset data!"
  })
})
})
.catch(error=>{
  //error while clearing exsisting records
  console.log(error);
  res.json({
    status:"FAILED",
    message:"Clearing exsisting reset records failed"
  })
})
}


//Actually reset the password
router.post("/resetPassword",(req,res)=>{

  let {userId,resetString,newPassword}=req.body;

  PasswordReset.find({userId})
  .then(result=>{
    if(result.length>0){
// password reset record exist so we proceed
const {expiresAt}=result[0];
const hashedResetString=result[0].resetString;

//checking for expired reset string
if(expiresAt<Date.now()){
  PasswordReset
  .deleteOne({userId})
  .then(()=>{
    //Reset record deleted successfully

    res.json({
      status:"FAILED",
      message:"Password reset link has expired"
    })
  })
  .catch(error=>{
    //deletion failed
    console.log(error);
    res.json({
      status:"FAILED",
      message:"Clearing password reset record failed."
    })
  })
}else{
  //valid reset record exists so we validate the reset string
  //First compare the hashed string

bcrypt
.compare(resetString,hashedResetString)
.then((result)=>{

if(result){
  //strings matched
  //hash password again

  const saltRounds=10;
  bcrypt
  .hash(newPassword,saltRounds)
  .then(hashedNewPassword=>{
    //update user password

User.
updateOne({_id:userId},{password:hashedNewPassword})
.then(()=>{
  //update completed. Now delete reset record
  PasswordReset
  .deleteOne({userId})
  .then(()=>{
//both user record and reset record updated


res.json({
  status:"SUCCESS",
  message:"Password has been rest successfully."
})
  })
  .catch(error=>{ 
    console.log(error)
    res.json({
      status:"FAILED",
message:"An error occurred while finalizing password reset"    
    })
  })
})
.catch(error=>{
  console.log(error);
  res.json({
    status:"FAILED",
    message:"Updating user password failed."
  })
})
})
  .catch(error=>{
    console.log(error);
    res.json({
      status:"FAILED",
      message:"An error occurred while hashing new password.",
    })
  })
}
else{
  //Existing record but incorrect reset string passed

  res.json({
    status:"FAILED",
    message:"Comparing password reset strings failed"
  })
}
})
.catch(error=>{
  res.json({
    status:"FAILED",
    message:"Comparing password reset strings failed."
  })
})
}
    }
    else{
      //password reset record doesn't exist
      res.json({
        status:"FAILED",
        message:"Password reset request not found"
      })
    }
  })
  .catch(error=>{
    console.log(error)
    res.json({
      status:"FAILED",
      message:"Checking for exixting password reset record failed."
    })
  })
})


module.exports = router;
