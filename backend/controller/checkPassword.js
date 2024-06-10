const UserModel = require("../models/UserModel");
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

async function checkPassword(request, response) {
    console.log(process.env.JWT_SECRET_KEY);

    try {
        const { password, userId } = request.body;

        if (!password || !userId) {
            return response.status(400).json({
                message: "User ID and password are required",
                error: true
            });
        }

        const user = await UserModel.findById(userId);

        if (!user) {
            return response.status(404).json({
                message: "User not found",
                error: true
            });
        }

        const verifyPassword = await bcryptjs.compare(password, user.password);

        if (!verifyPassword) {
            return response.status(400).json({
                message: "Incorrect password",
                error: true
            });
        }

        const tokenData = {
            id: user._id,
            email: user.email
        };

        const token = jwt.sign(tokenData, process.env.JWT_SECRET_KEY, { expiresIn: '350d' });

        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        };

        return response.cookie('token', token, cookieOptions).status(200).json({
            message: "Login successful",
            token: token,
            success: true
        });

    } catch (error) {
        console.error(error);
        return response.status(500).json({
            message: error.message || "An unexpected error occurred",
            error: true
        });
    }
}

module.exports = checkPassword;
