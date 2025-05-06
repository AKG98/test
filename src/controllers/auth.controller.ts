import { Request, Response } from "express";
import UserModel from "../models/user.model";
import bcryptjs from "bcryptjs";
import {generateAccessToken,generateRefreshToken,verifyAccessToken,verifyRefreshToken} from "../utils/jwt";

// Type definition for the User
type User = {
  name?: string; 
  email: string;
  password: string;
  refreshToken?: string; 
  _id?: string; 
};

interface IRequestUser extends Request {
  user?: { _id: string }; 
  userId?: string; 
}

export async function signup(req: IRequestUser, res: Response): Promise<void> {
  try {
    const { name, email, password }: User = req.body;

    // Check if the user already exists
    const userExists = await UserModel.findOne({ email });
    if (userExists) {
      res.status(400).json({ success: false, message: "User already exists" });
      return;
    }

    // Hash the password
    const hashedPassword = await bcryptjs.hash(password, 10);

    // Create a new user and save to DB
    const user = new UserModel({ name, email, password: hashedPassword });
    await user.save();

    // Respond with success
    res
      .status(201)
      .json({ success: true, message: "User created successfully" });
  } catch (error) {
    if (error instanceof Error) {
      res.status(500).json({
        success: false,
        message: `Internal server error: ${error.message}`,
      });
    } else {
      res
        .status(500)
        .json({ success: false, message: "Internal server error" });
    }
  }
}

export async function signin(req: IRequestUser, res: Response): Promise<void> {
  try {
    const { email, password }: User = req.body;

    // Find user by email
    const user = await UserModel.findOne({ email });
    if (!user) {
      res.status(409).json({ success: false, message: "User Not Found" });
      return;
    }

    // Compare the password with the stored hash
    const validUser = await bcryptjs.compare(password, user.password);
    if (!validUser) {
      res.status(409).json({ success: false, message: "Invalid Password" });
      return;
    }

    // Generate JWT token
    const accessToken = generateAccessToken(user._id.toString());
    const refreshToken = generateRefreshToken(user._id.toString());
    user.refreshToken = refreshToken; // Store the refresh token in the user document
    await user.save(); // Save the user document with the new refresh token

    // Send the token as a cookie
    res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: false,
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
    })
    .json({ message: 'Login successful' });
  
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function refreshToken(req: Request, res: Response): Promise<void> {
  const token = req.cookies?.refreshToken;
  if (!token) {
    res.sendStatus(401).json({ message: "No refresh token provided" });
    return;
  }

  try {
    const payload = verifyRefreshToken(token) as { id: string };
    const user = await UserModel.findById(payload.id);
    if (!user || user.refreshToken !== token) {
      res.sendStatus(403).json({ message: "Invalid refresh token" });
      return;
    }

    const newAccessToken = generateAccessToken(user._id.toString());
    const newRefreshToken = generateRefreshToken(user._id.toString());
    user.refreshToken = newRefreshToken;
    await user.save();

    res
        .cookie("accessToken", newAccessToken, {
            httpOnly: true,
            secure: false,
        })
        .cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: false,
        })
        .json({success:true, message: 'Token Refreshed' });

  } catch (err) {
    res.sendStatus(403);
  }
}

export async function currentUser(req: IRequestUser,res: Response): Promise<void> {
  try {
    const user = await UserModel.findById(req.userId).select(
      "-password -refreshToken"
    );
    if (!user) {
      res.status(404).json({ success: false,message: "User not found" });
      return;
    }
    res.status(200).json({ success: true, user });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function updateUserProfile(req: IRequestUser,res: Response): Promise<void> {
  try {
    const { name, email } = req.body;
    const user = await UserModel.findById(req.userId);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    user.name = name ?? user.name;
    user.email = email ?? user.email;
    await user.save();

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function deleteUser(req: IRequestUser,res: Response): Promise<void> {
  try {
    if (!req.user) {
      res
        .status(401)
        .json({ success: false, message: "User not authenticated" });
      return;
    }

    const deletedUser = await UserModel.findByIdAndDelete(req.user._id);

    if (!deletedUser) {
      res.status(404).json({ success: false, message: "User not found" });
      return;
    }

    res
      .status(200)
      .json({ success: true, message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function logout(req: Request, res: Response): Promise<void> {
    const token = req.cookies?.refreshToken;
    if (!token) {
      res.sendStatus(204);
      return;
    }
  
    const user = await UserModel.findOne({ refreshToken: token });
    if (user) {
      user.refreshToken = '';
      await user.save();
    }
  
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: false
    });
    res.json({ message: 'Logged out successfully' });
}