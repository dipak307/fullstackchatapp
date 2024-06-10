const jwt = require('jsonwebtoken');
const UserModel = require('../models/UserModel');

const getUserDetailsFromToken = async (token) => {
    try {
        if (!token) {
            return {
                message: "Session expired",
                logout: true,
            };
        }

        console.log(token);
        console.log("JWT Secret Key: ", process.env.JWT_SECRET_KEY);

        const decoded = await jwt.verify(token, process.env.JWT_SECRET_KEY);

        if (!decoded || !decoded.id) {
            return {
                message: "Invalid token",
                logout: true,
            };
        }

        const user = await UserModel.findById(decoded.id).select('-password');

        if (!user) {
            return {
                message: "User not found",
                logout: true,
            };
        }

        return user;

    } catch (error) {
        console.error(error);
        return {
            message: "Invalid token or session expired",
            logout: true,
        };
    }
};

module.exports = getUserDetailsFromToken;
