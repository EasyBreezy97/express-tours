const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const AppError = require("../utils/appError");
const catchAsync = require("./../utils/catchAsync");

const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    }); //create token
};

exports.signup = catchAsync(async (req, res, next) => {
    const { name, email, password, passwordConfirm } = req.body;

    const newUser = await User.create({
        name,
        email,
        password,
        passwordConfirm,
    });

    const token = signToken(newUser._id);

    res.status(201).json({
        status: "success",
        token,
        data: {
            user: newUser,
        },
    });
});

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    //check if email and password exists
    if (!email || !password) {
        return next(new AppError("Please provide email and password", 400));
    }

    //check if user exists && password is correct
    const user = await User.findOne({ email }).select("+password");

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new AppError("Incorrect email or password", 401));
    }

    // If ok, send token
    const token = signToken(user._id)

    res.status(200).json({
        status: "success",
        token,
    });
});
