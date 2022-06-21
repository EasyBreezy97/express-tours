const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "User must have a name"],
    },
    email: {
        type: String,
        trim: true,
        required: [true, "User must have an email"],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, "Please provide a valid email"],
    },
    photo: String,
    password: {
        type: String,
        required: [true, "Please provide a password"],
        minlength: 8,
        select: false,
    },
    passwordConfirm: {
        type: String,
        required: [true, "Please confirm a password"],
        validate: {
            //works ONLY on save and create
            validator: function (el) {
                return el === this.password;
            },
            message: "Passwords are not the same",
        },
        select: false,
    },
});

userSchema.pre("save", async function (next) {
    // Only run this is password was modified
    if (!this.isModified("password")) return next();
    //hash password const of 12
    this.password = await bcrypt.hash(this.password, 12);
    //delete password confirm field
    this.passwordConfirm = undefined;

    next();
});

userSchema.methods.correctPassword = async function (
    candidatePassword,
    userPassword,
) {
    return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model("User", userSchema);

module.exports = User;
