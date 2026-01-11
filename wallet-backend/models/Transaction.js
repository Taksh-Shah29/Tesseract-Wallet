import mongoose from "mongoose";

const TxSchema = new mongoose.Schema({
  senderUsername: String,
  receiverUsername: String,
  senderAddress: String,
  receiverAddress: String,
    senderCountry: String,      // ⭐ NEW
  receiverCountry: String,    // ⭐ NEW
  hash: String,
  amount: String,
  chain: String,
  timestamp: { type: Date, default: Date.now }
});

const Transaction = mongoose.model("Transaction", TxSchema);
export default Transaction;
