import bcrypt from "bcryptjs"
import User from "../models/User.js"
import jwt from "jsonwebtoken"

export const register = async (req, res, next) => {
  try {
    console.log("Register Request Body:", req.body); // 👈 log this

    const { name, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "Email already exists" });

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const newUser = new User({
      name,
      email,
      password: hash,
    });

    await newUser.save();
    console.log("User saved:", newUser); // 👈 log this

    const accessToken = jwt.sign(
      { id: newUser._id, isAdmin: newUser.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "none",
    };

    const { password: _, isAdmin, ...otherDetails } = newUser._doc;
    res.status(200).cookie("accessToken", accessToken, options).json({
      user: { ...otherDetails },
      isAdmin,
    });
  } catch (err) {
    console.error("Register error:", err); // 👈 show full error
    next(err);
  }
};



export const login = async(req, res, next)=>{
  try{
    console.log("Login Body:", req.body); // 👈 log incoming data

    const user = await User.findOne({email: req.body.email});
    if (!user) {
      return res.status(400).json({message:"Email not found"});
    }

    const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({message:"Invalid password"});
    }

    const accessToken = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'none'
    };

    const { password, isAdmin, ...otherDetails } = user._doc;
    res.status(200).cookie("accessToken", accessToken, options).json({ user: otherDetails, isAdmin });
  } catch(err){
    console.error("LOGIN ERROR:", err);  // 👈 this will print real error
    next(err);
  }
}


export const logout = async (req, res, next) => {
  try{
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: true,
    });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    next(err);
  }
};