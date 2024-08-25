import { utils, Wallet, Provider } from "zksync-ethers";
import * as ethers from "ethers";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";

// load env file
import dotenv from "dotenv";
dotenv.config();

const DEPLOYER_PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY || "";

export default async function (hre: HardhatRuntimeEnvironment) {
  // @ts-ignore target zkSyncSepoliaTestnet in config file which can be testnet or local
  const provider = new Provider("https://sepolia.era.zksync.dev");
  const wallet = new Wallet(DEPLOYER_PRIVATE_KEY).connect(provider);
  const deployer = new Deployer(hre, wallet);
  const deadman = await deployer.loadArtifact("DeadmanSwitch");

  // Bridge funds if the wallet on ZKsync doesn't have enough funds.
  // const depositAmount = ethers.parseEther('0.1');
  // const depositHandle = await deployer.zkWallet.deposit({
  //   to: deployer.zkWallet.address,
  //   token: utils.ETH_ADDRESS,
  //   amount: depositAmount,
  // });
  // await depositHandle.wait();

  const deadmanFactory = await deployer.deploy(deadman);
  const deadmanAddress = await deadmanFactory.getAddress();
  console.log(`Deadman Module address: ${deadmanAddress}`);

  console.log(`Done!`);
}
