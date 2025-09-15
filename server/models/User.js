import mongoose from "mongoose";
import bcrypt from "bcryptjs";


const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    credits: { type: Number, default: 200 }
});

// Hash password before saving the user
userSchema.pre('save', async function (next) {
    if(!this.isModified('password')) {
        return next(); // If password is not modified, proceed to next middleware
        // This is important to avoid re-hashing the password on every save
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next(); // Proceed to next middleware
})

const User = mongoose.model('User', userSchema);

export default User;
