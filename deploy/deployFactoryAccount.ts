import { utils, Wallet } from "zksync-ethers";
import * as ethers from "ethers";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";
import "dotenv/config";

export default async function (hre: HardhatRuntimeEnvironment) {
  const DEPLOYER_PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY || "";

  // Private key of the account used to deploy
  const wallet = new Wallet(DEPLOYER_PRIVATE_KEY);
  const deployer = new Deployer(hre, wallet);
  const factoryArtifact = await deployer.loadArtifact("AAwesomeFactory");
  const aaArtifact = await deployer.loadArtifact("Account");
  // Getting the bytecodeHash of the account
  const bytecodeHash = utils.hashBytecode(aaArtifact.bytecode);

  const factory = await deployer.deploy(
    factoryArtifact,
    [bytecodeHash],
    undefined,
    [aaArtifact.bytecode]
  );
  console.log("ok");

  const factoryAddress = await factory.getAddress();

  console.log(`AA factory address: ${factoryAddress}`);
}
