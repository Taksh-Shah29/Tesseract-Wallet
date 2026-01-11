import { useState } from "react";
import axios from "axios";
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  TextField,
  Button,
  Card,
  CardContent,
  Grid,
  Box,
  Divider,
  Paper,
} from "@mui/material";
import Autocomplete from "@mui/material/Autocomplete";

const API = "https://tesseract-wallet.onrender.com";

export default function App() {
  const [username,setUsername] = useState("");
  const [password,setPassword] = useState("");
  const [country, setCountry] = useState("");

  const [token,setToken] = useState("");
  const [role,setRole] = useState("");
  const [address,setAddress] = useState("");
  const [balance,setBalance] = useState("");
  const [sendTo,setSendTo] = useState("");
  const [amount,setAmount] = useState("");
  const [chain, setChain] = useState("sepolia");

  const [userTx, setUserTx] = useState([]);
  const [tokens, setTokens] = useState([]);
  
  const [userOptions, setUserOptions] = useState([]);

  // Admin
  const [stats,setStats] = useState(null);
  const [topUsers,setTopUsers] = useState([]);
  const [adminTx, setAdminTx] = useState([]);
  const [adminUsers,setAdminUsers] = useState([]);
  const [manageUser,setManageUser] = useState("");
  const [newRole,setNewRole] = useState("user");
  const [banState,setBanState] = useState(false);

  // ---------------- AUTH ----------------
  const register = async()=>{
    await axios.post(`${API}/register`,{username,password,country});
    alert("Registered Successfully");
  };

  const login = async()=>{
    const res = await axios.post(`${API}/login`,{username,password});
    setToken(res.data.token);
    setAddress(res.data.address);
    setUsername(res.data.username);
    setRole(res.data.role);
  };

  const logout = ()=>{
    setToken("");
    setRole("");
    setAddress("");
    setBalance("");
    setUserTx([]);
    setTokens([]);
  };

  // ---------------- WALLET ----------------
  const showBalance = async()=>{
    const res = await axios.get(`${API}/balance/${chain}/${address}`);
    setBalance(res.data.balance);
  };

  const sendEth = async()=>{
    const res = await axios.post(
      `${API}/send`,
      { toUsername: sendTo, amount, chain },
      { headers:{ Authorization:`Bearer ${token}` } }
    );
    alert(`Sent to ${sendTo}\nHash: ${res.data.hash}`);
  };

  const loadTx = async()=>{
    const res = await axios.get(`${API}/user-tx/${username}`);
    setUserTx(res.data);
  };

  const loadTokens = async()=>{
    const res = await axios.get(`${API}/tokens/${chain}/${address}`);
    setTokens(res.data);
  };

  const searchUsers = async (value) => {
  if (!value) {
    setUserOptions([]);
    return;
  }

  const res = await axios.get(
    `${API}/users/search?q=${value}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );

  setUserOptions(res.data.map(u => u.username));
};



  // ---------------- ADMIN ----------------
  const loadAdmin = async()=>{
    const res = await axios.get(`${API}/admin/stats`,{
      headers:{ Authorization:`Bearer ${token}` }
    });
    setStats(res.data);
    setTopUsers(res.data.topUsers);
  };

  const loadUsers = async()=>{
    const res = await axios.get(`${API}/admin/users`,{
      headers:{ Authorization:`Bearer ${token}` }
    });
    setAdminUsers(res.data);
  };

  const loadCrossBorderTx = async () => {
  const res = await axios.get(`${API}/admin/cross-border-tx`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  setAdminTx(res.data);
};

  const changeRole = async()=>{
    await axios.post(
      `${API}/admin/set-role`,
      { username: manageUser, role:newRole },
      { headers:{ Authorization:`Bearer ${token}` } }
    );
    alert("Role Updated");
    loadUsers();
  };

  const banUser = async()=>{
    await axios.post(
      `${API}/admin/ban`,
      { username: manageUser, banned:banState },
      { headers:{ Authorization:`Bearer ${token}` } }
    );
    alert(banState ? "User Banned" : "User Unbanned");
    loadUsers();
  };

  return (
    <>
      {/* NAVBAR */}
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h5">Web3 Wallet</Typography>
        </Toolbar>
      </AppBar>

      <Container maxWidth="md" sx={{ mt:4 }}>
        <Grid container spacing={3}>

          {/* AUTH */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6">
                  {token ? "Logged In" : "Login / Register"}
                </Typography>

                {!token && (
                  <>
                    <TextField fullWidth label="Username" sx={{ mt:2 }}
                      onChange={e=>setUsername(e.target.value)} />
                    <TextField fullWidth label="Password" type="password" sx={{ mt:2 }}
                      onChange={e=>setPassword(e.target.value)} />
                      <TextField fullWidth label="Country" sx={{ mt:2 }}
                      onChange={e=>setCountry(e.target.value)} />

                    <Box sx={{ mt:2 }}>
                      <Button variant="contained" onClick={register} sx={{ mr:2 }}>
                        Register
                      </Button>
                      <Button variant="contained" color="success" onClick={login}>
                        Login
                      </Button>
                    </Box>
                  </>
                )}

                {token && (
                  <Box sx={{ mt:2 }}>
                    <Typography>Logged in as: <b>{username}</b></Typography>
                    <Typography>Role: <b>{role}</b></Typography>
                    <Typography sx={{ mt:1 }}><b>{address}</b></Typography>
                    <Button sx={{ mt:2 }} variant="contained" color="error" onClick={logout}>
                      Logout
                    </Button>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* DASHBOARD */}
          {token && (
            <>
              {/* CHAIN SELECT */}
              <Grid item xs={12}>
                <Paper sx={{ p:2 }}>
                  <Typography variant="h6">Select Blockchain</Typography>
                  <select
                    style={{ padding:"10px", marginTop:"10px" }}
                    value={chain}
                    onChange={(e)=>setChain(e.target.value)}
                  >
                    <option value="sepolia">Ethereum Sepolia</option>
                    <option value="amoy">Polygon Amoy</option>
                  </select>
                </Paper>
              </Grid>

              {/* ADMIN DASHBOARD */}
              {role === "admin" && (
                <>
                  <Grid item xs={12}>
                    <Paper sx={{ p:3 }}>
                      <Typography variant="h5">Admin Dashboard</Typography>
                      <Button variant="contained" onClick={loadAdmin}>
                        Load Admin Stats
                      </Button>

                      {stats && (
                        <Box sx={{ mt:2 }}>
                          <Typography>Total Users: {stats.totalUsers}</Typography>
                          <Typography>Total Tx: {stats.totalTx}</Typography>
                          <Typography>Total Volume: {stats.totalVolume}</Typography>
                          <Typography>Active Users: {stats.activeUsers}</Typography>

                          <Typography sx={{ mt:2 }} variant="h6">Top Users</Typography>
                          {topUsers.map((u,i)=>(
                            <Typography key={i}>
                              #{i+1} {u._id} — {u.count} tx
                            </Typography>
                          ))}
                        </Box>
                      )}
                    </Paper>
                  </Grid>

                  <Grid item xs={12}>
                    <Paper sx={{ p:3 }}>
                      <Typography variant="h5">User Management</Typography>
                      <Button variant="contained" onClick={loadUsers}>Load Users</Button>

                      {adminUsers.map((u,i)=>(
                        <Box key={i} sx={{ mt:2 }}>
                          <Typography>{u.username} | {u.role} | {u.banned ? "BANNED" : "ACTIVE"}</Typography>
                        </Box>
                      ))}

                      <Divider sx={{ my:2 }} />
                      <TextField fullWidth label="Username" onChange={e=>setManageUser(e.target.value)} />

                      <select style={{ padding:"10px", marginTop:"10px" }}
                        onChange={e=>setNewRole(e.target.value)}>
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                      </select>

                      <Button sx={{ ml:2 }} variant="contained" onClick={changeRole}>
                        Update Role
                      </Button>

                      <Box sx={{ mt:2 }}>
                        <select style={{ padding:"10px" }}
                          onChange={e=>setBanState(e.target.value === "true")}>
                          <option value="false">Unban</option>
                          <option value="true">Ban</option>
                        </select>

                        <Button sx={{ ml:2 }} variant="contained" color="error" onClick={banUser}>
                          Apply
                        </Button>
                      </Box>
                    </Paper>
                  </Grid>

                  <Grid item xs={12}>
  <Paper sx={{ p:3 }}>
    <Typography variant="h6">
      🌍 Cross-Border Transactions
    </Typography>

    <Button
      variant="contained"
      sx={{ mt:1 }}
      onClick={loadCrossBorderTx}
    >
      Load Cross-Border Tx
    </Button>

    {adminTx.length === 0 && (
      <Typography sx={{ mt:2 }}>
        No cross-border transactions
      </Typography>
    )}

    {adminTx.map((t,i)=>(
      <Box
        key={i}
        sx={{ mt:2, p:2, border:"1px solid #ddd", borderRadius:"8px" }}
      >
        <Typography>
          <b>{t.senderUsername}</b> → <b>{t.receiverUsername}</b>
        </Typography>

        <Typography>
          {t.senderCountry} → {t.receiverCountry}
        </Typography>

        <Typography>
          Amount: {t.amount} {t.chain === "sepolia" ? "ETH" : "POL"}
        </Typography>

        <Typography sx={{ fontSize:"12px", color:"gray" }}>
          Chain: {t.chain}
        </Typography>
      </Box>
    ))}
  </Paper>
</Grid>

                </>
              )}

              {/* BALANCE */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p:3 }}>
                  <Typography variant="h6">Wallet Balance</Typography>
                  <Typography variant="h4">
                    {balance || "0.0"} {chain === "sepolia" ? "ETH" : "POL"}
                  </Typography>
                  <Button sx={{ mt:2 }} variant="contained" onClick={showBalance}>
                    Refresh
                  </Button>
                </Paper>
              </Grid>

              {/* USER TX */}
              <Grid item xs={12}>
                <Paper sx={{ p:3 }}>
                  <Typography variant="h6">Transaction History</Typography>
                  <Button variant="contained" onClick={loadTx}>Load</Button>

                  {userTx.map((t,i)=>(
                    <Box key={i} sx={{ mt:2 }}>
                      <Typography>
                        {t.senderUsername} ➝ {t.receiverUsername}
                      </Typography>
                      <Typography>
                        {t.amount} {t.chain === "sepolia" ? "ETH" : "POL"}
                      </Typography>
                      <Typography sx={{ fontSize:"12px" }}>{t.hash}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>

             
              {/* SEND */}
              <Grid item xs={12} md={6}>
  <Paper sx={{ p:3 }}>
    <Typography variant="h6">Send Crypto</Typography>

    {/* Username Autocomplete */}
    <Autocomplete
      freeSolo
      options={userOptions}
      sx={{ mt:1 }}
      onInputChange={(e, value) => {
        setSendTo(value);
        searchUsers(value);
      }}
      onChange={(e, value) => setSendTo(value)}
      renderInput={(params) => (
        <TextField
          {...params}
          fullWidth
          label="Receiver Username"
        />
      )}
    />

    <TextField
      fullWidth
      label={`Amount (${chain === "sepolia" ? "ETH" : "POL"})`}
      sx={{ mt:2 }}
      onChange={e=>setAmount(e.target.value)}
    />

    <Button
      sx={{ mt:2 }}
      variant="contained"
      onClick={sendEth}
    >
      Send
    </Button>
  </Paper>
</Grid>

            </>
          )}
        </Grid>
      </Container>
    </>
  );
}
