import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import mongoose from "mongoose";

interface IRequestUser extends Request {
    user?: {
        _id: mongoose.Types.ObjectId;
    };
}

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
export const authenticate = async (
    req: IRequestUser,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const token = req.cookies.accessToken;
    
    if (!token) {
        res.status(401).json({
            success: false,
            message: "Token no found"
        });
        return; // Added return statement
    }
    try {

        const decoded = jwt.verify(token, JWT_SECRET) as {
            id: string;
        };
        (req as any).userId = decoded.id;
        next();

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            res.status(401).json({
                success: false,
                message: "Invalid tokens"
            });
            return;
        }

        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
        return;
    }
};