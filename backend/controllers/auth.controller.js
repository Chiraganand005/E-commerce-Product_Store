import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { redis } from "../lib/redis.js"; // Import the Redis instance


dotenv.config();

const generateTokens = (userId) => {
    const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
    return { accessToken, refreshToken };
}

const storeRefreshToken = async (userId, refreshToken) => {
    // Store the refresh token in Redis or any other storage
    // For example, using Redis:
    await redis.set(`refreshToken:${userId}`, refreshToken, 'EX', 60 * 60 * 24 * 7); // Store for 7 days
}

const setCookies = (res, accessToken, refreshToken) => {
    res.cookie('accessToken', accessToken, {    
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
    });
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
}


// controllers for signup , login and logout 
export const signup = async(req,res)=>{
    const {email,name , password} = req.body;
    
    try {
        const userExists = await User.findOne({email});
        if( userExists){
            return res.status(400).json({message : "User already exists"});
        }
        const user = await User.create({ name, email , password});

        const {accessToken, refreshToken} = generateTokens(user._id);
        await storeRefreshToken(user._id, refreshToken);

        setCookies(res, accessToken, refreshToken);

        return res.status(201).json({ user:{
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role
        } , message: "user created Successfully"});
    } catch (error) {
        console.error("error in user module" , error.message)
        return res.status(500).json({message : error.message});
    }
}

export const login = async(req,res)=>{
    const {email, password} = req.body;
    
    try {
        const user = await User.findOne({ email });
        if (user && await user.comparePassword(password)) {
            const { accessToken, refreshToken } = generateTokens(user._id);
            await storeRefreshToken(user._id, refreshToken);

            setCookies(res, accessToken, refreshToken);

            return res.status(200).json({ user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }, message: "Login successful" });
        }
        return res.status(401).json({ message: "Invalid email or password" });
    } catch (error) {
        console.error("error in login" , error.message);
        return res.status(500).json({message : "Server Error", error: error.message});
    }    
}

export const logout = async(req,res)=>{ 
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            await redis.del(`refreshToken:${decoded.userId}`); // Remove the refresh token from Redis
        }
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');    
        return res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        console.error("error in logout" , error.message);
        return res.status(500).json({message : "Server Error", error: error.message});
        
    }
}

export const refreshToken = async(req, res) => {
    try{
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({ message: "No refresh token provided" });
        }

        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userId = decoded.userId;

        // Check if the refresh token exists in Redis
        const storedRefreshToken = await redis.get(`refreshToken:${userId}`);
        if (storedRefreshToken !== refreshToken) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const accessToken = jwt.sign({ userId:decoded.userId}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
        
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.json({ accessToken, message: "Access token refreshed successfully" });

    }catch(error) {
        console.error("error in refresh token" , error.message);
        return res.status(500).json({message : "Server Error", error: error.message});
    }
}
