import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: { type: String },
  country: { type: String, required: true },   // ⭐ NEW
  ethAddress: { type: String },
  encryptedPrivateKey: { type: String },
  role: { type: String, default: "user" },
  banned: { type: Boolean, default: false }  // ⭐ NEW

});

const User = mongoose.model("User", UserSchema);
export default User;
