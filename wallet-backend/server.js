import 'dotenv/config';
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import Moralis from "moralis";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "./models/User.js";
import { ethers } from "ethers";
import CryptoJS from "crypto-js";
import Transaction from "./models/Transaction.js";




const app = express();
app.use(cors());
app.use(express.json());

await Moralis.start({ apiKey: process.env.MORALIS_API_KEY });

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Mongo Connected"))
  .catch(err => console.log(err));

  // ================= PROVIDER HELPER =================

const getProvider = (chain) => {
  if(chain === "sepolia"){
    return new ethers.JsonRpcProvider("https://rpc.ankr.com/eth_sepolia");
  }

  if(chain === "amoy"){
    return new ethers.JsonRpcProvider("https://rpc-amoy.polygon.technology");
  }

  throw new Error("Unsupported chain");
};


// ---------------- AUTH MIDDLEWARE ----------------
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if(!token) return res.status(401).json({ msg:"No Token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user)=>{
    if(err) return res.status(401).json({ msg:"Invalid Token" });
    req.user = user;
    next();
  });
}

// ---------------- ADMIN MIDDLEWARE ----------------
function isAdmin(req,res,next){
  if(!req.user) return res.status(401).json({ msg:"Unauthorized" });
  if(req.user.role !== "admin") return res.status(403).json({ msg:"Admin Only" });
  next();
}


// ---------------- REGISTER ----------------
app.post("/register", async (req,res)=>{
  try{
    const { username, password ,country} = req.body;

    const exist = await User.findOne({ username });
    if(exist) return res.status(400).json({ msg:"Username already exists" });

    const hashed = await bcrypt.hash(password,10);

    const wallet = ethers.Wallet.createRandom();
    
    const encryptedKey = CryptoJS.AES.encrypt(wallet.privateKey, process.env.ENCRYPT_SECRET).toString();

    const user = new User({
      username,
      password: hashed,
      country,                     // ⭐ SAVE COUNTRY
      ethAddress: wallet.address,
      encryptedPrivateKey: encryptedKey
    });

    await user.save();

    res.json({
      msg:"Registered",
      username,
      address: wallet.address
    });

  }catch(e){
    res.status(500).json({ error:e.message });
  }
});


app.get("/admin/stats", auth, isAdmin, async(req,res)=>{
  try{
    const totalUsers = await User.countDocuments();

    const totalTx = await Transaction.countDocuments();

    const totalVolumeAgg = await Transaction.aggregate([
      { $group: { _id:null, total:{ $sum:{ $toDouble:"$amount" } } } }
    ]);

    const totalVolume = totalVolumeAgg[0]?.total || 0;

    const activeUsersAgg = await Transaction.aggregate([
      { 
        $group:{
          _id:null,
          users:{ $addToSet:"$senderUsername" }
        }
      }
    ]);

    const activeUsers = activeUsersAgg[0]?.users.length || 0;

    const topUsers = await Transaction.aggregate([
      {
        $group:{
          _id:"$senderUsername",
          count:{ $sum:1 }
        }
      },
      { $sort:{ count:-1 } },
      { $limit:5 }
    ]);

    res.json({
      totalUsers,
      totalTx,
      totalVolume,
      activeUsers,
      topUsers
    });

  }catch(e){
    res.status(500).json({ error:e.message });
  }
});


// ---------------- LOGIN ----------------
app.post("/login", async(req,res)=>{
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if(!user) return res.status(404).json({ msg:"User not found" });

   if (user.banned)
    return res.status(403).json({ msg: "You are banned" });

  const match = await bcrypt.compare(password,user.password);
  if(!match) return res.status(401).json({ msg:"Wrong Password" });

  const token = jwt.sign(
  { id:user._id, role:user.role },
  process.env.JWT_SECRET
);


  res.json({
    msg:"Login Success",
    token,
    username:user.username,
    address:user.ethAddress,
    role: user.role
});
});


// ---------------- LOGOUT ----------------
app.post("/logout",(req,res)=>{
  res.json({ msg:"Logout Success. Just delete token in frontend." });
});





// ---------------- ADMIN: GET ALL USERS ----------------
app.get("/admin/users", auth, isAdmin, async(req,res)=>{
  const users = await User.find().select("-password -encryptedPrivateKey");
  res.json(users);
});



// ---------------- ADMIN: SET ROLE ----------------
app.post("/admin/set-role", auth, isAdmin, async(req,res)=>{
  const { username, role } = req.body;

  if(!["user","admin"].includes(role))
    return res.status(400).json({ msg:"Invalid role" });

  await User.findOneAndUpdate(
    { username },
    { role }
  );

  res.json({ msg:"Role Updated" });
});

// ---------------- ADMIN: BAN / UNBAN USER ----------------
app.post("/admin/ban", auth, isAdmin, async(req,res)=>{
  const { username, banned } = req.body;

  await User.findOneAndUpdate(
    { username },
    { banned }
  );

  res.json({ msg: banned ? "User Banned" : "User Unbanned" });
});


// ---------------- ADMIN: CROSS-BORDER TRANSACTIONS ----------------
app.get("/admin/cross-border-tx", auth, isAdmin, async (req, res) => {
  try {
    const tx = await Transaction.find({
      $expr: { $ne: ["$senderCountry", "$receiverCountry"] }
    }).sort({ timestamp: -1 });

    res.json(tx);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



// ---------------- SHOW PRIVATE KEY (OWN USER ONLY) ----------------
app.get("/private-key", auth, async(req,res)=>{
  const user = await User.findById(req.user.id);
  
  const decrypted = CryptoJS.AES.decrypt(
    user.encryptedPrivateKey,
    process.env.ENCRYPT_SECRET
  ).toString(CryptoJS.enc.Utf8);

  res.json({ privateKey: decrypted });
});


// ---------------- GET BALANCE ----------------
app.get("/balance/:chain/:address", async(req,res)=>{
  try{
    const { chain, address } = req.params;

    const chainId =
      chain === "sepolia" ? "0xaa36a7" :
      chain === "amoy" ? "0x13882" :
      null;

    if(!chainId) return res.status(400).json({ msg:"Invalid chain" });

    const result = await Moralis.EvmApi.balance.getNativeBalance({
      address,
      chain: chainId
    });

    res.json({ balance: ethers.formatEther(result.raw.balance) });

  }catch(e){
    res.status(500).json({ error:e.message });
  }
});

// ---------------- GET TOKENS ----------------
app.get("/tokens/:chain/:address", async(req,res)=>{
  try{
    const { chain, address } = req.params;

    const chainId =
      chain === "sepolia" ? "0xaa36a7" :
      chain === "amoy" ? "0x13882" :
      null;

    if(!chainId) return res.status(400).json({ msg:"Invalid chain" });

    const result = await Moralis.EvmApi.token.getWalletTokenBalances({
      address,
      chain: chainId
    });

    res.json(result.raw.result);

  }catch(e){
    res.status(500).json({ error:e.message });
  }
});



// ---------------- TRANSACTIONS ----------------
app.get("/tx/:chain/:address", async(req,res)=>{
  const { chain, address } = req.params;

  const chainId =
    chain === "sepolia" ? "0xaa36a7" :
    chain === "amoy" ? "0x13882" :
    null;

  if(!chainId) return res.status(400).json({ msg:"Invalid chain" });

  const result = await Moralis.EvmApi.transaction.getWalletTransactions({
    address,
    chain: chainId
  });

  res.json(result.raw.result);
});


// ---------------- USERNAME TO ADDRESS ----------------
app.get("/resolve/:username", async(req,res)=>{
  const user = await User.findOne({ username:req.params.username });
  if(!user) return res.status(404).json({ msg:"User not found" });
  res.json({ address:user.ethAddress });
});


// ---------------- SEND ETH ----------------
app.post("/send", auth, async(req,res)=>{
  try{
    const { toUsername, amount, chain } = req.body;

    const provider = getProvider(chain);

    const sender = await User.findById(req.user.id);
    if(!sender) return res.status(404).json({ msg:"Sender not found" });

    const receiver = await User.findOne({ username: toUsername });
    if(!receiver) return res.status(404).json({ msg:"Receiver not found" });

    const decrypted = CryptoJS.AES.decrypt(
      sender.encryptedPrivateKey,
      process.env.ENCRYPT_SECRET
    ).toString(CryptoJS.enc.Utf8);

    const wallet = new ethers.Wallet(decrypted, provider);

    const tx = await wallet.sendTransaction({
      to: receiver.ethAddress,
      value: ethers.parseEther(amount)
    });

    // ⭐ SAVE TX IN DATABASE
    await Transaction.create({
      senderUsername: sender.username,
      receiverUsername: receiver.username,
      senderAddress: sender.ethAddress,
      receiverAddress: receiver.ethAddress,
        senderCountry: sender.country,          // ⭐
  receiverCountry: receiver.country,      // ⭐
      hash: tx.hash,
      amount,
      chain
    });

    res.json({
      msg:"Transaction Sent",
      hash: tx.hash,
      chain
    });

  }catch(e){
    res.status(500).json({ error:e.message });
  }
});

app.get("/user-tx/:username", async(req,res)=>{
  const { username } = req.params;

  const tx = await Transaction.find({
    $or: [
      { senderUsername: username },
      { receiverUsername: username }
    ]
  }).sort({ timestamp: -1 });

  res.json(tx);
});
  
// ---------------- SEARCH USERS ----------------
app.get("/users/search", auth, async (req, res) => {
  const { q } = req.query;

  if (!q) return res.json([]);

  const users = await User.find({
    username: { $regex: q, $options: "i" }
  })
    .select("username")
    .limit(5);

  res.json(users);
});





// ================= START SERVER =================

app.listen(process.env.PORT || 5000, () => {
  console.log("Server Running");
});

