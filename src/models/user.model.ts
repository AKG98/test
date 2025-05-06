
import { Schema, model } from "mongoose";


const UserSchema = new Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
        default: "",
    },
    },{timestamps: true});

const UserModel = model("User", UserSchema);

export default UserModel;